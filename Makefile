TEST=

db:
	docker-compose up db -d --remove-orphans

start:
	docker-compose up -d

stop:
	docker-compose stop

clean:
	docker-compose down

build:
	docker-compose build web

test:
	docker-compose run web python manage.py test --keepdb --verbosity=2 ${TEST}

e2e:
	docker-compose --file docker-compose.yml --file docker-compose.test.yml up --build --exit-code-from tests db web tests

wait_mysql:
	docker-compose run web bash -c 'wait-for-it db:3306'

migrate:
	docker-compose run web python manage.py migrate

lint: # lint currently staged files
	pre-commit run

lint-all: # lint all files in repository
	pre-commit run --all-files

check: wait_mysql
	docker-compose run web python manage.py makemigrations --check

migrations: wait_mysql
	docker-compose run web python manage.py makemigrations

settings:
	docker-compose run web python manage.py diffsettings

docs:
	docker-compose run web sphinx-build -b html -d docs/_build/doctrees docs docs/_build/html
