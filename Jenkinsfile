// Pipeline for KMV Network Monitor on the kind cluster "mycluster" (test-pgsql, 172.16.30.124).
// All files are in the root of the repository (no folders needed).
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 25, unit: 'MINUTES')
    }

    environment {
        APP          = 'kmv-monitor'
        NAMESPACE    = 'kmv-monitor'
        IMAGE        = "kmv-monitor:${env.BUILD_NUMBER}"
        KIND_CLUSTER = 'mycluster'
        KUBECONFIG   = '/var/jenkins_home/kubeconfig'
    }

    stages {
        stage('Check tools') {
            steps {
                sh '''
                  docker version --format 'Docker {{.Server.Version}}'
                  kind version
                  kubectl get nodes
                '''
            }
        }

        stage('Check secret') {
            steps {
                // Passwords are never stored in Git. The Secret is created once on the server (README step 1).
                sh '''
                  if ! kubectl -n $NAMESPACE get secret kmv-monitor-secrets >/dev/null 2>&1; then
                    echo "ERROR: Secret kmv-monitor-secrets is missing in namespace $NAMESPACE."
                    echo "Create it on the server first (see README, step 1)."
                    exit 1
                  fi
                '''
            }
        }

        stage('Build image') {
            steps {
                // The Dockerfile also compiles isp-monitor.py, so a syntax error fails here.
                sh 'docker build -t $IMAGE .'
            }
        }

        stage('Load image into kind') {
            steps {
                sh 'kind load docker-image $IMAGE --name $KIND_CLUSTER'
            }
        }

        stage('Deploy database') {
            steps {
                sh '''
                  kubectl apply -f k8s-namespace.yaml
                  kubectl apply -f k8s-postgres.yaml
                  kubectl -n $NAMESPACE rollout status statefulset/kmv-db --timeout=180s
                '''
            }
        }

        stage('Deploy app') {
            steps {
                sh '''
                  sed "s|IMAGE_PLACEHOLDER|$IMAGE|" k8s-app.yaml | kubectl apply -f -
                  kubectl -n $NAMESPACE rollout status deployment/$APP --timeout=180s
                  kubectl -n $NAMESPACE get pods -o wide
                '''
            }
            post {
                failure {
                    sh '''
                      echo "Rollout failed. Details:"
                      kubectl -n $NAMESPACE describe deployment/$APP | tail -n 25 || true
                      kubectl -n $NAMESPACE logs deployment/$APP --tail=40 || true
                      echo "Rolling back to the previous version"
                      kubectl -n $NAMESPACE rollout undo deployment/$APP || true
                    '''
                }
            }
        }

        stage('Smoke test') {
            steps {
                sh '''
                  kubectl -n $NAMESPACE run smoke-$BUILD_NUMBER --rm -i --restart=Never \
                    --image=curlimages/curl:8.10.1 -- \
                    sh -c "curl -fsS --retry 5 --retry-delay 3 --retry-all-errors http://$APP/healthz && \
                           curl -fsS -o /dev/null -w 'login page: %{http_code}\\n' http://$APP/login"
                '''
            }
        }
    }

    post {
        success {
            echo "Deployed ${IMAGE} to namespace ${NAMESPACE}."
        }
        always {
            sh 'docker image prune -f || true'
        }
    }
}
