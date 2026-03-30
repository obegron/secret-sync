package main

import (
	"context"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

func (c *controller) runPush(ctx context.Context) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.localClient,
		0,
		informers.WithNamespace(namespaceOrAll(c.cfg.sourceNamespace)),
	)
	secretInformer := factory.Core().V1().Secrets().Informer()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			start := time.Now()
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				c.recordError("push_reconcile_failed")
				log.Printf("reconcile add %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			sec, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			start := time.Now()
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				c.recordError("push_reconcile_failed")
				log.Printf("reconcile update %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
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
			start := time.Now()
			if err := c.handleDelete(ctx, sec); err != nil {
				c.metrics.deleteErrors.Add(1)
				c.recordError("push_delete_failed")
				log.Printf("handle delete %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
		},
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		log.Fatal("cache sync failed")
	}
	c.ready.Store(true)

	<-ctx.Done()
}
