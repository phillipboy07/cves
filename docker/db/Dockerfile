# use MSSQL 2017 image on Ubuntu 16.04
FROM microsoft/mssql-server-linux

# create directory within SQL container for database files
RUN mkdir -p /opt/mssql-scripts


# copy or add the database files from host to container
ADD . /opt/mssql-scripts

# set environment variables
ENV MSSQL_SA_PASSWORD=P@55w0rd
ENV ACCEPT_EULA=Y

# run initial scripts
RUN chmod +x -R /opt/mssql-scripts
RUN /opt/mssql-scripts/entrypoint.sh