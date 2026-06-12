pipeline {
    agent any

    environment {
        DOCKER_USER = 'gxfdev'
        REPO_NAME = 'secure-channel'
        TAG = "${env.BUILD_NUMBER}"
        RECEIVER_IP = '192.168.157.207'
        SENDER_IP = '192.168.157.208'
        // 从 Jenkins 凭据中读取 PAT（前提是你添加了 Secret text 类型且 ID 为 github-ghcr-token）
        GHCR_PAT = credentials('github-ghcr-token')
    }

    stages {
        stage('拉取代码') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/gxfdev/secure-channel.git',
                    credentialsId: 'github-cred'
            }
        }

        stage('构建 Docker 镜像') {
            steps {
                script {
                    docker.build("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}")
                }
            }
        }

        stage('推送镜像到 GitHub Container Registry') {
            steps {
                script {
                    docker.withRegistry('https://ghcr.io', 'github-ghcr-token') {
                        docker.image("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}").push()
                        docker.image("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}").push("latest")
                    }
                }
            }
        }

        stage('部署到接收端 node7') {
            steps {
                sshPublisher(publishers: [
                    sshPublisherDesc(configName: 'node7', transfers: [
                        sshTransfer(execCommand: """
                            echo '${GHCR_PAT}' | docker login ghcr.io -u ${DOCKER_USER} --password-stdin
                            docker pull ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                            docker stop netsec-receiver || true
                            docker rm netsec-receiver || true
                            docker run -d \
                              --name netsec-receiver \
                              --network host \
                              --cap-add NET_ADMIN --cap-add NET_RAW \
                              -v /root/captured_data:/app/captured_data \
                              -e MODE=receiver \
                              -e FLASK_HOST=0.0.0.0 \
                              -e LISTEN_PORT=9999 \
                              ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                        """)
                    ])
                ])
            }
        }

        stage('部署到发送端 node8') {
            steps {
                sshPublisher(publishers: [
                    sshPublisherDesc(configName: 'node8', transfers: [
                        sshTransfer(execCommand: """
                            echo '${GHCR_PAT}' | docker login ghcr.io -u ${DOCKER_USER} --password-stdin
                            docker pull ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                            docker stop netsec-sender || true
                            docker rm netsec-sender || true
                            docker run -d \
                              --name netsec-sender \
                              --network host \
                              --cap-add NET_ADMIN --cap-add NET_RAW \
                              -v /root/captured_data:/app/captured_data \
                              -e MODE=sender \
                              -e RECEIVER_HOST=${RECEIVER_IP} \
                              -e FLASK_HOST=0.0.0.0 \
                              -e RECEIVER_PORT=9999 \
                              ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                        """)
                    ])
                ])
            }
        }
    }

    post {
        success {
            echo '流水线执行成功！两个节点均已更新。'
        }
        failure {
            echo '流水线执行失败，请检查控制台输出。'
        }
    }
}
