# User Management Project Setup and Run Guide

This guide will help you set up and run the User Management project using Docker and Docker Compose.

## Prerequisites

- Docker
- Docker Compose

## Setup Instructions

Follow these steps to set up the project:

1. **Build the Docker images**

    ```sh
    docker-compose build
    ```

2. **Start the containers**

    ```sh
    docker-compose up -d
    ```

3. **Initialize the database**

    ```sh
    docker exec django_app python init_db.py
    docker exec django_app python manage.py makemigration
    docker exec django_app python manage.py migrate
    ```

4. **Create initial permissions and roles**

    ```sh
    docker exec django_app python manage.py create_initial_permissions_roles
    ```

5. **Create a super user with custom details**

    ```sh
    docker exec django_app python manage.py create_super_custom_user
    ```

## Accessing the Application

Once the setup is complete, you can access the application at `http://localhost:8000`.

## Environment Variables

The following environment variables are used in the project and can be configured in the `docker-compose.yml` file:

- `DJANGO_SECRET_KEY`: The secret key for the Django application.
- `DJANGO_DEBUG`: Set to `True` for development. Change to `False` for production.
- `DJANGO_ALLOWED_HOSTS`: A list of allowed hosts for the Django application.
- `DATABASE_URL`: The URL for the PostgreSQL database connection.
- `DASHBOARD_URL`: The URL for the Dashboard.
- `DATA_MODELER_URL`: The URL for the Data Modeler.
- `DATA_PROCESSOR_URL`: The URL for the Data Processor.
- `STARROCKS_URL`: The URL for Starrocks.
- `AIRFLOW_URL`: The URL for Airflow.

Make sure to update these variables with the appropriate values for your environment.

## Stopping the Containers

To stop the running containers, use the following command:

```sh
docker-compose down
```

Troubleshooting
If you encounter any issues, you can check the logs of the containers using the following command:
```sh
docker-compose logs
```

For more detailed logs of a specific service, use:
```sh
docker-compose logs <service_name>
```
Replace <service_name> with the name of the service you want to check (e.g., django_app or db).

