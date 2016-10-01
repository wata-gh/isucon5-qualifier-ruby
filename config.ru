require_relative './app.rb'

use Rack::Session::Cookie, secret: 'isucon5q'
run Isucon5::WebApp
