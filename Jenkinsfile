pipeline {
    agent any
    environment {
        TARGET_URL = "${params.TARGET_URL ?: 'https://example.com/'}"
    }
    parameters {
        string(name: 'TARGET_URL', defaultValue: 'https://example.com/', description: 'URL to scan')
    }
    stages {
        stage('Build') {
            steps { sh 'cargo build --release --bin lancer' }
        }
        stage('Scan') {
            steps {
                sh '''
                    ./target/release/lancer cert init --dir ./ca
                    ./target/release/lancer project new --path ./scan.lancer --name "CI"
                    ./target/release/lancer scan full "$TARGET_URL" --project ./scan.lancer
                    ./target/release/lancer report --project ./scan.lancer --format html --out lancer.html
                    ./target/release/lancer report --project ./scan.lancer --format sarif --out lancer.sarif
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'lancer.html, lancer.sarif', fingerprint: true
            recordIssues tool: sarif(pattern: 'lancer.sarif')
        }
    }
}
