pipeline {
  agent any
  parameters {
    booleanParam(name: 'RUN_NATIVE', defaultValue: false,
      description: 'Require native tests, coverage and release artifact; fails until runtime inputs exist')
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
          env.OCTOPUS_RUST_DIR = fileExists('services/octopus-rust/Jenkinsfile') ? 'services/octopus-rust' : '.'
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
        dir(env.OCTOPUS_RUST_DIR) {
          sh 'bash scripts/ci/native.sh'
          archiveArtifacts artifacts: 'artifacts/octopus-coverage/**,artifacts/octopus', fingerprint: true
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
