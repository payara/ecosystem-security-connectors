#!groovy

pipeline {

    agent {
        label 'general-purpose'
    }
    tools {
        jdk "zulu-11"
        maven "maven-3.6.3"
    }
    environment {
        JAVA_HOME = tool("zulu-11")
        MAVEN_OPTS = '-Xmx2G -Djavax.net.ssl.trustStore=${JAVA_HOME}/jre/lib/security/cacerts'
        payaraBuildNumber = "${BUILD_NUMBER}"
    }
    stages {

        stage('Build') {
            steps {
                script {
                    echo '*#*#*#*#*#*#*#*#*#*#*#*#  Building SRC  *#*#*#*#*#*#*#*#*#*#*#*#*#*#*#'
                    sh """mvn -B -V -ff -e clean install --strict-checksums \
                        -Djavadoc.skip -Dsource.skip"""
                    echo '*#*#*#*#*#*#*#*#*#*#*#*#    Built SRC   *#*#*#*#*#*#*#*#*#*#*#*#*#*#*#'
                }
            }
        }
    }
}
