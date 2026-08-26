import multiprocessing

bind = "unix:/run/flask-assets/flask-assets.sock"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gthread"
threads = 2
timeout = 120
keepalive = 2
accesslog = "/var/log/flask-assets/access.log"
errorlog = "/var/log/flask-assets/error.log"
loglevel = "info"
preload_app = True
