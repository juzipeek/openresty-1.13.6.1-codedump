[NGX_HTTP_DYUPS_MODULE模块解析](http://wangfakang.github.io/sky2)

更新机制：

1.  某个worker收到更新upstream的请求，将这个修改同步到消息队列中。
2.  所有worker定时查询该消息队列的消息（定时间隔由dyups_read_msg_timeout参数指定，默认1s）。这里的问题在于，消息队列是否会无限增长，答案是不会的，具体做法是每个消息保存一个计数器，每worker处理一次时递增该计数器，当等于worker数量时就可以删除该消息。另外消息本身还会保存保存该消息的worker pid，这样就不会重复执行同一个消息。

