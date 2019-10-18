USR=usr.ubanquity.io
REPO=v3test.ubanquity.io:5000
CONTAINER=finance:$1

docker pull $USR/$CONTAINER
docker tag  $USR/$CONTAINER $REPO/$CONTAINER
docker push                $REPO/$CONTAINER

docker service rm finance
docker service create \
    --restart-condition  any               \
    --constraint engine.labels.zone==mgt   \
    -l com.ubanquity.console.visible=true \
    -l com.ubanquity.console.min=1         \
    -l com.ubanquity.console.max=2         \
    --name finance \
    --replicas=1  \
    --mount type=bind,source=/data/ubanquity/log,target=/log \
    --mount type=bind,source=/data/ubanquity/conf,target=/conf  \
    --mount type=bind,source=/etc/hostname,target=/etc/host_hostname \
    --endpoint-mode dnsrr \
    --network usl                          \
    -u ubanquity \
    --update-failure-action rollback --update-max-failure-ratio 0 --update-monitor 10s --update-order stop-first --update-parallelism 1 \
    $REPO/$CONTAINER
