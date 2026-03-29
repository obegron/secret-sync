package main

import (
	"context"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type pullQueueAction string

const (
	pullActionReconcile pullQueueAction = "reconcile"
	pullActionDelete    pullQueueAction = "delete"
)

type pullQueueItem struct {
	action    pullQueueAction
	namespace string
	name      string
	secret    *corev1.Secret
}

func (c *controller) runPull(ctx context.Context) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.hostClient,
		0,
		informers.WithNamespace(c.cfg.sourceNamespace),
	)
	secretInformer := factory.Core().V1().Secrets().Informer()
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pull-secrets")
	defer queue.ShutDown()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			c.enqueuePullReconcile(queue, sec.Namespace, sec.Name)
		},
		UpdateFunc: func(_, newObj interface{}) {
			sec, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			c.enqueuePullReconcile(queue, sec.Namespace, sec.Name)
		},
		DeleteFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				sec, ok = tombstone.Obj.(*corev1.Secret)
				if !ok {
					return
				}
			}
			c.enqueuePullDelete(queue, sec)
		},
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		log.Fatal("cache sync failed")
	}

	for i := 0; i < 2; i++ {
		go c.runPullWorker(ctx, queue, secretInformer.GetIndexer())
	}
	c.ready.Store(true)

	<-ctx.Done()
}

func (c *controller) enqueuePullReconcile(queue workqueue.TypedRateLimitingInterface[interface{}], namespace, name string) {
	queue.Add(pullQueueItem{
		action:    pullActionReconcile,
		namespace: namespace,
		name:      name,
	})
}

func (c *controller) enqueuePullDelete(queue workqueue.TypedRateLimitingInterface[interface{}], src *corev1.Secret) {
	queue.Add(pullQueueItem{
		action:    pullActionDelete,
		namespace: src.Namespace,
		name:      src.Name,
		secret:    src.DeepCopy(),
	})
}

func (c *controller) runPullWorker(ctx context.Context, queue workqueue.TypedRateLimitingInterface[interface{}], indexer cache.Indexer) {
	for c.processNextPullItem(ctx, queue, indexer) {
	}
}

func (c *controller) processNextPullItem(ctx context.Context, queue workqueue.TypedRateLimitingInterface[interface{}], indexer cache.Indexer) bool {
	raw, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(raw)

	item, ok := raw.(pullQueueItem)
	if !ok {
		queue.Forget(raw)
		log.Printf("ignoring unexpected queue item type %T", raw)
		return true
	}

	var err error
	switch item.action {
	case pullActionReconcile:
		start := time.Now()
		key := fmt.Sprintf("%s/%s", item.namespace, item.name)
		obj, exists, getErr := indexer.GetByKey(key)
		if getErr != nil {
			err = fmt.Errorf("index lookup %s: %w", key, getErr)
			break
		}
		if !exists {
			queue.Forget(raw)
			return true
		}
		sec, castOK := obj.(*corev1.Secret)
		if !castOK {
			queue.Forget(raw)
			log.Printf("ignoring index object for %s with unexpected type %T", key, obj)
			return true
		}
		err = c.reconcilePull(ctx, sec)
		if err != nil {
			c.metrics.reconcileErrors.Add(1)
			c.recordError("pull_reconcile_failed")
			log.Printf("reconcile pull %s failed: %v", key, err)
		} else {
			c.recordSuccess(time.Since(start))
		}
	case pullActionDelete:
		if item.secret != nil {
			start := time.Now()
			err = c.handleDeletePull(ctx, item.secret)
			if err != nil {
				c.metrics.deleteErrors.Add(1)
				c.recordError("pull_delete_failed")
				log.Printf("handle pull delete %s/%s failed: %v", item.namespace, item.name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
		}
	default:
		queue.Forget(raw)
		log.Printf("ignoring queue item with unknown action %q", item.action)
		return true
	}

	if err == nil {
		queue.Forget(raw)
		return true
	}

	queue.AddRateLimited(raw)
	return true
}
