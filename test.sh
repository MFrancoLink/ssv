#!/bin/bash

set -x

CHARTS=( node-1 node-2 node-3 node-4 )
CLUSTER=( a b c d )

# Loop through the charts and deploy them
for CHART in "${CHARTS[@]}";
do 
  for CLUSTER in "${CLUSTER[@]}";
  do
  helm3.5.4 upgrade --install $CHART-$CLUSTER --namespace ssv --set image.tag=$IMAGE_TAG --values .k8/helm3/base-values.yaml --values .k8/helm3/ssv-node-cluster-$CLUSTER/cluster-values.yaml --values .k8/helm3/ssv-node-cluster-$CLUSTER/$CHART-$CLUSTER/node-values.yaml .k8/helm3/ssv-node-cluster-$CLUSTER/$CHART-$CLUSTER/ --dry-run --debug;
  done
done
