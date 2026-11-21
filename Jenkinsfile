pipeline {
  agent any
  parameters {
    booleanParam(name: 'RUN_NATIVE', defaultValue: false,
      description: 'Require native tests, coverage and release artifact')
    string(name: 'PARENT_REVISION', defaultValue: '', description: 'For standalone native builds, the full ssl-proxy commit pinning this checkout')
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
    disableConcurrentBuilds(abortPrevious: true)
    skipDefaultCheckout(true)
    timestamps()
    timeout(time: 90, unit: 'MINUTES')
  }
  stages {
    stage('Checkout') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        deleteDir()
        checkout scm
      }
    }
    stage('Validate delivery scaffold') {
      steps {
        script {
          env.OCTOPUS_RUST_DIR = fileExists('services/octopus-rs/Jenkinsfile') ? 'services/octopus-rs' : '.'
        }
        dir(env.OCTOPUS_RUST_DIR) {
          sh 'bash scripts/ci/test.sh'
        }
      }
    }
    stage('Native tests and release build') {
      when { expression { params.RUN_NATIVE } }
      options { timeout(time: 75, unit: 'MINUTES') }
      steps {
        script {
          if (env.OCTOPUS_RUST_DIR == '.') {
            if (!(params.PARENT_REVISION ==~ /[0-9a-f]{40}/)) {
              error('Standalone native validation requires PARENT_REVISION')
            }
            dir('umbrella-fixtures') {
              checkout([$class: 'GitSCM', branches: [[name: params.PARENT_REVISION]],
                        userRemoteConfigs: [[url: 'https://github.com/zlovtnik/ssl-proxy.git']]])
              env.OCTOPUS_UMBRELLA_ROOT = pwd()
            }
            sh 'test "$(git rev-parse HEAD)" = "$(git -C "$OCTOPUS_UMBRELLA_ROOT" rev-parse HEAD:services/octopus-rs)"'
          } else {
            sh 'python3 scripts/octopus_image_contract.py source --native'
          }
        }
        dir(env.OCTOPUS_RUST_DIR) {
          sh 'bash scripts/ci/native.sh'
          archiveArtifacts artifacts: 'artifacts/octopus-coverage/**,artifacts/octopus', fingerprint: true
        }
      }
      post {
        unsuccessful {
          dir(env.OCTOPUS_RUST_DIR) {
            archiveArtifacts artifacts: 'artifacts/octopus-coverage/**', allowEmptyArchive: true
          }
        }
      }
    }
  }
  post {
    always {
      script {
        if (params.RUN_NATIVE && env.OCTOPUS_RUST_DIR) {
          dir(env.OCTOPUS_RUST_DIR) {
            timeout(time: 5, unit: 'MINUTES') {
              sh label: 'Reclaim CI resources', script: 'if [ -f scripts/ci/cleanup.sh ]; then bash scripts/ci/cleanup.sh; fi'
            }
          }
        }
      }
    }
  }
}
