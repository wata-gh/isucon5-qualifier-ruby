@dir = "/home/isucon/webapp/ruby"
worker_processes 2
preload_app false

listen "/tmp/unicorn.sock"
pid "#{@dir}/unicorn.pid"
stderr_path "#{@dir}/log/unicorn.stderr.log"
stdout_path "#{@dir}/log/unicorn.stdout.log"
