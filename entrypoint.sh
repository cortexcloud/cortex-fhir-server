#!/bin/sh

export ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD:=`cat ${ELASTICSEARCH_PASSWORD_FILE}`}
export HAPI_DATASOURCE_PASSWORD=${HAPI_DATASOURCE_PASSWORD:=`cat ${HAPI_DATASOURCE_PASSWORD_FILE}`}

# Execute the Java application
java --class-path "/app/main.war" \
-Dloader.path="main.war!/WEB-INF/classes/,main.war!/WEB-INF/,/app/extra-classes" \
org.springframework.boot.loader.PropertiesLauncher "$@"