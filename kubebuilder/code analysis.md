# doController

[func (blder *Builder) doController(r reconcile.Reconciler) error](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/sigs.k8s.io/controller-runtime/pkg/builder/controller.go#L278)

初始化controller

# doWatch

[src := &source.Kind{Type: typeForSrc}](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/sigs.k8s.io/controller-runtime/pkg/builder/controller.go#L225)

[func (ks *Kind) Start(ctx context.Context, handler handler.EventHandler, queue workqueue.RateLimitingInterface, prct ...predicate.Predicate) error](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/sigs.k8s.io/controller-runtime/pkg/source/source.go#L105)

调用AddEventHandler给informer添加了一个事件处理的handler, 当资源发生创建 / 删除 / 修改时, 会调用这个句柄的OnAdd / OnUpdate / OnDelete. 调用后会把Request入队, Requset里包含着NamespacedName.

# start
[func (c *Controller) Start(ctx context.Context) error](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/sigs.k8s.io/controller-runtime/pkg/internal/controller/controller.go#L148)

[c.processNextWorkItem(ctx)](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/sigs.k8s.io/controller-runtime/pkg/internal/controller/controller.go#L227)

mgr start后会调用controller的start, 接着调用controller的processNextWorkItem, processNextWorkItem会从队列里面取出Request, 并调用reconcileHandler, reconcileHandler会调用Reconcile, 并处理返回值. 如果RequeueAfter>0, 会把请求重新入队.

# informer
informer的reflector会listwatch资源, 当资源发生增删查的时候, 把资源加入deltafifo. 

deltafifo保存着资源以及对其进行的操作.deltafifo里面主要有两项, 一项是相同类型的不同资源的队列([]string, string是资源的ns-name), 另一项是map[string][]Delta, Delta里存放着操作类型和资源.

pop从deltafifo的队列中取出第一项, 并把第一项的所有delta交给HandleDeltas处理, HandleDeltas又调用distribute处理deltas, 同时把deltas加入indexer. distribute又会调用listener.add(obj). listener的handler就是我们调用AddEventHandler添加的.


[listener.add(obj)](https://github.com/pjjwjw/kubebuilder-code-learning/blob/c0ee044804dcec34754a122979f97bb6b9dfb054/vendor/k8s.io/client-go/tools/cache/shared_informer.go#L613)