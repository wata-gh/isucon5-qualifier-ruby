require 'json'
require 'rack/utils'
require 'rack/request'
require 'mysql2'
require 'mysql2-cs-bind'
require 'tilt/erubis'
require 'erubis'
require 'redis'
require 'hiredis'
require './mysql2_query_logger'
require 'awesome_print'

module Isucon5
  class AuthenticationError < StandardError; end
  class PermissionDenied < StandardError; end
  class ContentNotFound < StandardError; end
  module TimeWithoutZone
    def to_s
      strftime("%F %H:%M:%S")
    end
  end
  ::Time.prepend TimeWithoutZone
end

class Isucon5::WebApp
  VIEWS_DIR = "#{__dir__}/views"

  def self.view(name)
    @views ||= {}
    @views[name] ||= begin
      Erubis::FastEruby.new(File.read(File.join(VIEWS_DIR, "#{name}.erb")))
    end
  end

  def self.call(env)
    self.new(env).call
  end

  def initialize(env)
    @env = env
    @status = nil
    @headers = {}
    @body = []
  end

  module ResponseMethods
    def response
      [@status || 200, @headers, @body]
    end

    def content_type(type)
      @headers['Content-Type'] = type
    end

    def render(template, layout: :layout, locals: {})
      @headers['Content-Type'] ||= 'text/html'
      @status ||= 200
      if layout
        @body = [erb(layout) { erb(template) } ]
      else
        @body = [erb(template)]
      end
    end

    def erb(name)
      Isucon5::WebApp.view(name).result(binding)
    end

    def not_found
      @status = 404
      @headers = {'Content-Type' => 'text/plain'}
      @body = ['not found']
    end

    def redirect(path)
      if @env['HTTP_VERSION'] == 'HTTP/1.1' && @env["REQUEST_METHOD"] != 'GET'
        @status = 303
      else
        @status = 302
      end

      @headers['Location'] = path
    end
  end

  module Helpers
    def request
      @request ||= Rack::Request.new(@env)
    end

    def session
      @session ||= request.session
    end

    def params
      @params ||= request.params
    end

    def config
      @config ||= {
        db: {
          host: ENV['ISUCON5_DB_HOST'] || 'localhost',
          port: ENV['ISUCON5_DB_PORT'] && ENV['ISUCON5_DB_PORT'].to_i,
          username: ENV['ISUCON5_DB_USER'] || 'root',
          password: ENV['ISUCON5_DB_PASSWORD'],
          database: ENV['ISUCON5_DB_NAME'] || 'isucon5q',
        },
      }
    end

    def db
      Thread.current[:request] = request
      return Thread.current[:isucon5_db] if Thread.current[:isucon5_db]
      client = Mysql2::Client.new(
        host: config[:db][:host],
        port: config[:db][:port],
        username: config[:db][:username],
        password: config[:db][:password],
        database: config[:db][:database],
        reconnect: true,
      )
      client.query_options.merge!(symbolize_keys: true)
      Thread.current[:isucon5_db] = client
      client
    end

    def redis
      Thread.current[:redis] ||=
        Redis.new(:host => "127.0.0.1", :port => 6379, driver: :hiredis)
    end

    def authenticate(email, password)
      result = JSON.parse(redis.get(email), symbolize_names: true)
      unless result
        raise Isucon5::AuthenticationError
      end
      session[:user_id] = result[:id]
      result
    end

    def current_user
      return @user if @user
      unless session[:user_id]
        return nil
      end
      @user = JSON.parse(redis.get(session[:user_id].to_s), symbolize_names: true)
      unless @user
        session[:user_id] = nil
        session.clear
        raise Isucon5::AuthenticationError
      end
      @user
    end

    def authenticated!
      unless current_user
        redirect '/login'
        return false
      end
      return true
    end

    def get_user(user_id)
      user = JSON.parse(redis.get(user_id.to_s), symbolize_names: true)
      raise Isucon5::ContentNotFound unless user
      user
    end

    def user_from_account(account_name)
      user = JSON.parse(redis.get(account_name), symbolize_names: true)
      raise Isucon5::ContentNotFound unless user
      user
    end

    def friends
      return @friends if defined? @friends
      query = 'SELECT another FROM relations WHERE one = ?'
      @friends = {}
      db.xquery(query, current_user[:id]).each do |rel|
        @friends[rel[:another]] = rel
      end
      @friends
    end

    def is_friend?(another_id)
      friends[another_id] != nil
    end

    def is_friend_account?(account_name)
      is_friend?(user_from_account(account_name)[:id])
    end

    def permitted?(another_id)
      another_id == current_user[:id] || is_friend?(another_id)
    end

    def mark_footprint(user_id)
      if user_id != current_user[:id]
        query = 'INSERT INTO footprints (user_id,owner_id) VALUES (?,?)'
        db.xquery(query, user_id, current_user[:id])
      end
    end

    PREFS = %w(
      未入力
      北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 新潟県 富山県
      石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 奈良県 和歌山県 鳥取県 島根県
      岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 熊本県 大分県 宮崎県 鹿児島県 沖縄県
    )
    def prefectures
      PREFS
    end

    def entry_by_id(entry_id)
      entry_query = <<SQL
SELECT
 id,
 SUBSTRING_INDEX(body, '\n', 1) AS title,
 created_at
FROM entries e
where id = ?
SQL
      entry = db.xquery(entry_query, entry_id).first
    end

    def cache_entries_of_friends(user_id, entry_id)
      entry = entry_by_id(entry_id)
      entry_owner = JSON.parse(redis.get(user_id), symbolize_names: true)
      html = <<EOS
<div class="friend-entry">
 <ul class="list-group">
  <li class="list-group-item entry-owner"><a href="/diary/entries/#{entry_owner[:account_name]}">#{entry_owner[:nick_name]}さん</a>:
  <li class="list-group-item entry-title"><a href="/diary/entry/#{entry[:id]}">#{entry[:title]}</a>
  <li class="list-group-item entry-created-at">投稿時刻:#{entry[:created_at]}
 </ul>
</div>
EOS

      cache = [entry[:created_at].to_datetime.to_time.to_i, html]
      friends.keys.each do |id|
        redis.zadd("entries_of_friends/#{id}", cache)
      end
    end

    def update_cache_entries_of_friends(user_id)
      friend_ids = db.xquery('select another from relations where one = ?', user_id).map {|rel| rel[:another]}

      entries_of_friends_query = <<SQL
SELECT
 id,
 SUBSTRING_INDEX(body, '\n', 1) AS title,
 user_id,
 created_at
FROM entries e
WHERE
 e.user_id in (#{friend_ids.join(',')})
ORDER BY created_at DESC
LIMIT 10
SQL
      entries_of_friends = db.xquery(entries_of_friends_query).map do |rel|
        entry_owner = JSON.parse(redis.get(rel[:user_id]), symbolize_names: true)
        html = <<EOS
<div class="friend-entry">
 <ul class="list-group">
  <li class="list-group-item entry-owner"><a href="/diary/entries/#{entry_owner[:account_name]}">#{entry_owner[:nick_name]}さん</a>:
  <li class="list-group-item entry-title"><a href="/diary/entry/#{rel[:id]}">#{rel[:title]}</a>
  <li class="list-group-item entry-created-at">投稿時刻:#{rel[:created_at]}
 </ul>
</div>
EOS
        [rel[:created_at].to_datetime.to_time.to_i, html]
      end
      redis.pipelined do
        key = "entries_of_friends/#{user_id}"
        redis.del(key)
        redis.zadd(key, entries_of_friends)
      end
    end
  end

#  error Isucon5::AuthenticationError do
#    session[:user_id] = nil
#    halt 401, erubis(:login, layout: false, locals: { message: 'ログインに失敗しました' })
#  end

#  error Isucon5::PermissionDenied do
#    halt 403, erubis(:error, locals: { message: '友人のみしかアクセスできません' })
#  end

#  error Isucon5::ContentNotFound do
#    halt 404, erubis(:error, locals: { message: '要求されたコンテンツは存在しません' })
#  end

  module Actions
    def get_login
      session.clear
      @message = '高負荷に耐えられるSNSコミュニティサイトへようこそ!'
      render :login, layout: nil
    end

    def post_login
      authenticate params['email'], params['password']
      redirect '/'
    end

    def get_logout
      session[:user_id] = nil
      session.clear
      redirect '/login'
    end

    def get_index
      return unless authenticated!

      profile = JSON.parse(redis.get("profiles/#{current_user[:id]}"), symbolize_names: true)
      ap profile

      entries_query = <<SQL
SELECT
 id,
 SUBSTRING_INDEX(body, '\n', 1) AS title,
 private
FROM entries
WHERE user_id = ?
ORDER BY created_at
LIMIT 5
SQL
      entries = db.xquery(entries_query, current_user[:id])
                .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry }

      comments_for_me_query = <<SQL
SELECT
  id,
  entry_id,
  user_id,
  comment,
  created_at
FROM comments c
WHERE entry_user_id = ?
ORDER BY c.created_at DESC
LIMIT 10
SQL
      comments_for_me = db.xquery(comments_for_me_query, current_user[:id])

      friend_ids = friends.keys.join(',')
      entries_of_friends = redis.zrevrange("entries_of_friends/#{current_user[:id]}", 0, 9)

      comments_of_friends_query = <<SQL
SELECT
  c.*,
  c.entry_user_id,
  u.account_name as entry_account_name,
  u.nick_name as entry_nick_name
FROM comments c
JOIN users u on c.entry_user_id = u.id
WHERE c.user_id IN (#{friend_ids})
AND (
  c.private = 0
  OR
  c.private = 1 AND (c.entry_user_id = ? OR c.entry_user_id IN (#{friend_ids}))
)
ORDER BY c.id DESC LIMIT 10
SQL

      comments_of_friends = db.xquery(comments_of_friends_query, current_user[:id])
      comments_users_hash = db.xquery("select id, account_name, nick_name from users where id in (#{comments_of_friends.map{|c| c[:user_id]}.join(',')})").each_with_object({}) do |rel, h|
        h[rel[:id]] = rel
      end

      friends_query = 'SELECT * FROM relations WHERE one = ? ORDER BY created_at DESC'
      friends_map = {}
      db.xquery(friends_query, current_user[:id]).each do |rel|
        friends_map[rel[:another]] ||= rel[:created_at]
      end
      friends = friends_map.map{|user_id, created_at| [user_id, created_at]}.sort_by{|a| a[1]}.reverse

      query = <<SQL
SELECT
  f.user_id,
  f.owner_id, DATE(f.created_at) AS date,
  MAX(f.created_at) AS updated,
  u.account_name,
  u.nick_name
FROM footprints f
JOIN users u ON f.owner_id = u.id
WHERE f.user_id = ?
GROUP BY f.user_id, f.owner_id, DATE(f.created_at)
ORDER BY updated DESC
LIMIT 10
SQL
      footprints = db.xquery(query, current_user[:id])

      @profile = profile || {}
      @entries =  entries
      @comments_for_me = comments_for_me
      @entries_of_friends = entries_of_friends
      @comments_of_friends = comments_of_friends
      @comments_users_hash = comments_users_hash
      @friends = friends
      @footprints = footprints
      render :index
    end

    def get_profile_account_name(account_name)
      return unless authenticated!
      owner = user_from_account(account_name)
      prof = JSON.parse(redis.get("profiles/#{owner[:id]}"), symbolize_names: true)
      prof = {} unless prof
      query = if permitted?(owner[:id])
                'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
              else
                'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5'
              end
      entries = db.xquery(query, owner[:id])
                .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
      mark_footprint(owner[:id])
      @owner = owner
      @profile = prof
      @entries = entries
      @private = permitted?(owner[:id])
      render :profile
    end

    def post_profile_account_name(account_name)
      return unless authenticated!
      if account_name != current_user[:account_name]
        raise Isucon5::PermissionDenied
      end
      args = [params['first_name'], params['last_name'], params['sex'], params['birthday'], params['pref']]

      prof = JSON.parse(redis.get("profiles/#{current_user[:id]}"), symbolize_names: true)
      if prof
        query = <<SQL
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL
        args << current_user[:id]
      else
        query = <<SQL
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL
        args.unshift(current_user[:id])
      end
      db.xquery(query, *args)

      # update cache
      prof[:first_name] = args[1]
      prof[:last_name] = args[2]
      prof[:sex] = args[3]
      prof[:birthday] = args[4]
      prof[:pref] = args[5]
      redis.set("profiles/#{current_user[:id]}", prof.to_json)
      redirect "/profile/#{account_name}"
    end

    def get_diary_entries_account_name(account_name)
      return unless authenticated!
      owner = user_from_account(account_name)
      query = if permitted?(owner[:id])
                'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
              else
                'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20'
              end
      entries = db.xquery(query, owner[:id])
                .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
      mark_footprint(owner[:id])
      query = <<SQL
select entry_id, count(1) count from comments
where entry_id in (#{entries.map {|e| e[:id]}.join(',')})
group by entry_id
SQL
      comment_count_hash = db.xquery(query).each_with_object(Hash.new(0)) do |rel, h|
        h[rel[:entry_id]] = rel[:count]
      end
      @owner = owner
      @entries = entries
      @myself = (current_user[:id] == owner[:id])
      @comment_count_hash = comment_count_hash
      render :entries
    end

    def get_diary_entry_entry_id(entry_id)
      return unless authenticated!
      entry = db.xquery('SELECT * FROM entries WHERE id = ?', entry_id).first
      raise Isucon5::ContentNotFound unless entry
      entry[:title], entry[:content] = entry[:body].split(/\n/, 2)
      entry[:is_private] = (entry[:private] == 1)
      owner = get_user(entry[:user_id])
      if entry[:is_private] && !permitted?(owner[:id])
        raise Isucon5::PermissionDenied
      end
      comments = db.xquery('SELECT * FROM comments WHERE entry_id = ?', entry[:id])
      mark_footprint(owner[:id])
      @owner = owner
      @entry = entry
      @comments = comments
      render :entry
    end

    def post_diary_entry
      return unless authenticated!
      query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)'
      body = (params['title'] || "タイトルなし") + "\n" + params['content']
      db.xquery(query, current_user[:id], (params['private'] ? '1' : '0'), body)
      cache_entries_of_friends(current_user[:id], db.last_id)
      redirect "/diary/entries/#{current_user[:account_name]}"
    end

    def post_diary_comment_entry_id(entry_id)
      return unless authenticated!
      entry_id = entry_id.to_i
      entry = db.xquery('SELECT user_id, private FROM entries WHERE id = ?', entry_id).first
      unless entry
        raise Isucon5::ContentNotFound
      end
      entry[:is_private] = (entry[:private] == 1)
      if entry[:is_private] && !permitted?(entry[:user_id])
        raise Isucon5::PermissionDenied
      end
      query = 'INSERT INTO comments (entry_id, entry_user_id, user_id, comment) VALUES (?,?,?,?)'
      db.xquery(query, entry_id, entry[:user_id], current_user[:id], params['comment'])
      redirect "/diary/entry/#{entry_id}"
    end

    def get_footprints
      return unless authenticated!
      query = <<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) as updated
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 50
SQL
      footprints = db.xquery(query, current_user[:id])
      @footprints = footprints
      render :footprints
    end

    def get_friends
      return unless authenticated!
      query = <<SQL
SELECT
  r.another,
  r.created_at,
  u.account_name,
  u.nick_name
FROM
  relations r LEFT JOIN users u ON u.id = r.another
WHERE
  r.one = ? ORDER BY r.created_at DESC
SQL
      list = db.xquery(query, current_user[:id])
      @friends = list
      render :friends
    end

    def post_friends_account_name(account_name)
      user = user_from_account(account_name)
      unless user
        raise Isucon5::ContentNotFound
      end
      db.xquery('INSERT INTO relations (one, another) VALUES (?,?), (?,?)', current_user[:id], user[:id], user[:id], current_user[:id])
      update_cache_entries_of_friends(current_user[:id])
      redirect '/friends'
    end

    def get_initialize
      query = <<SQL
SELECT
  u.id AS id,
  u.account_name AS account_name,
  u.nick_name AS nick_name,
  u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
SQL
      db.xquery(query).each do |rel|
        json = rel.to_json
        redis.set(rel[:id], json)
        redis.set(rel[:account_name], json)
        redis.set(rel[:email], json)
      end
      query = <<SQL
SELECT
  user_id,
  first_name,
  last_name,
  sex,
  birthday,
  pref,
  updated_at
FROM profiles
SQL
      db.xquery(query).each do |rel|
        redis.set("profiles/#{rel[:user_id]}", rel.to_json)
      end
      db.query("DELETE FROM relations WHERE id > 500000")
      db.query("DELETE FROM footprints WHERE id > 500000")
      db.query("DELETE FROM entries WHERE id > 500000")
      db.query("DELETE FROM comments WHERE id > 1500000")
    end
  end

  include ResponseMethods
  include Helpers
  include Actions
  def call
    case @env['REQUEST_METHOD']
    when 'GET'
      case @env['PATH_INFO']
      when "/"; get_index
      when "/initialize"; get_initialize
      when "/login"; get_login
      when "/logout"; get_logout
      when "/footprints"; get_footprints
      when "/friends"; get_friends
      when /^\/profile\/(.*)/
        get_profile_account_name($1)
      when /^\/diary\/entry\/(.*)/
        get_diary_entry_entry_id($1)
      when /^\/diary\/entries\/(.*)/
        get_diary_entries_account_name($1)
      else; not_found
      end

    when 'POST'
      case @env['PATH_INFO']
      when '/login'; post_login
      when '/diary/entry'; post_diary_entry
      when /^\/profile\/(.*)/
        post_profile_account_name($1)
      when /^\/diary\/comment\/(.*)/
        post_diary_comment_entry_id($1)
      when /^\/friends\/(.*)/
        post_friends_account_name($1)
      else; not_found
      end

    else
      not_found
    end

    @body = [@body] unless @body.respond_to?(:each)
    response
  end
end
