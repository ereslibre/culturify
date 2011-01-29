# -*- coding: utf-8 -*-

# This file is part of Culturify.
#
# Copyright (C) 2011 Rafael Fernández López <ereslibre@gmail.com>
#
# Throttle is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Throttle is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Throttle. If not, see <http://www.gnu.org/licenses/>.

require 'json'
require 'mongo'
require 'sinatra'
require 'digest/sha1'

# Error codes
INVALID_AUTH                    = 0
INVALID_USERNAME_OR_SESSION_ID  = 1
USER_ALREADY_EXISTS             = 2

# Misc
CURRENT_PATH = File.dirname(File.expand_path __FILE__)

class Success
  attr_reader :data
  def initialize(data = nil)
    @data = data
  end
  def to_json
    if @data
      { :status => 0, :data => @data }.to_json
    else
      { :status => 0 }.to_json
    end
  end
  def ==(other)
    @data == other.data
  end
end

class Error
  attr_reader :data
  def initialize(data = nil)
    @data = data
  end
  def to_json
    if @data
      { :status => 1, :data => @data }.to_json
    else
      { :status => 1 }.to_json
    end
  end
  def ==(other)
    @data == other.data
  end
end

module Culturify
  def self.random_hash
      Digest::SHA1.hexdigest File.read('/dev/urandom', 128)
  end
  def self.public_ddbb
    ddbb = File.open File.join(CURRENT_PATH, 'ddbb.json'), 'r'
    json = JSON.parse ddbb.read
    connection_data = json['public']
    connection = Mongo::Connection.new connection_data['host'], connection_data['port']
    ddbb = connection[connection_data['database']]
    ddbb.authenticate connection_data['full']['username'], connection_data['full']['password']
    ddbb
  end
  def self.private_ddbb
    ddbb = File.open File.join(CURRENT_PATH, 'ddbb.json'), 'r'
    json = JSON.parse ddbb.read
    connection_data = json['private']
    connection = Mongo::Connection.new connection_data['host'], connection_data['port']
    ddbb = connection[connection_data['database']]
    ddbb.authenticate connection_data['username'], connection_data['password']
    ddbb
  end
  def self.create_session(ddbb, username)
    session_id = Culturify.random_hash
    sessions = ddbb['sessions']
    sessions.update({ :username => username }, { :username   => username,
                                                 :session_id => session_id }, { :upsert => true })
    session_id
  end
end

get '/api/ddbb' do
  ddbb = File.open File.join(CURRENT_PATH, 'ddbb.json'), 'r'
  json = JSON.parse ddbb.read
  Success.new({ 'host'     => json['public']['host'],
                'port'     => json['public']['port'],
                'database' => json['public']['database'],
                'username' => json['public']['readonly']['username'],
                'password' => json['public']['readonly']['password'] }).to_json
end

post '/api/users' do
  # Retrieve request information
  data = JSON.parse request.body.read
  username = data['username']
  password = data['password']
  email    = data['email']

  # Connect to the public database
  public_ddbb = Culturify.public_ddbb

  public_users = public_ddbb['users']
  user = public_users.find_one({ :username => username })

  if user != nil
    return Error.new({ :error_code => USER_ALREADY_EXISTS }).to_json
  end

  # Connect to the private database
  private_ddbb = Culturify.private_ddbb
  private_users = private_ddbb['users']

  # Create the private username entry
  user_salt = Culturify.random_hash
  private_users.insert({ :username => username,
                         :password => Digest::SHA1.hexdigest("#{password}#{user_salt}"),
                         :salt     => user_salt,
                         :email    => email })

  # Create the public username entry
  public_users.insert({ :username => username })

  Success.new({ :session_id => Culturify.create_session(private_ddbb, username) }).to_json
end

delete '/api/user/:username/:session_id' do |username, session_id|
  # Connect to the private database
  private_ddbb = Culturify.private_ddbb

  sessions = public_ddbb['sessions']

  # Check whether the user exists
  user = sessions.find_one({ :username => username, :session_id => session_id })

  if session == nil
    return Error.new({ :error_code => INVALID_USERNAME_OR_SESSION_ID }).to_json
  end

  public_ddbb = Culturify.public_ddbb

  public_users = public_ddbb['users']
  private_users = private_ddbb['users']

  sessions.remove({ :username => username })
  public_users.remove({ :username => username })
  private_users.remove({ :username => username })

  Success.new.to_json
end

post '/api/sessions' do
  # Retrieve request information
  data = JSON.parse request.body.read
  username = data['username']
  password = data['password']

  # Connect to the private database
  ddbb = Culturify.private_ddbb

  # Check authentication information
  users = ddbb['users']
  user = users.find_one({ :username => username })

  if user == nil
    return Error.new({ :error_code => INVALID_AUTH }).to_json
  end

  computed_password = Digest::SHA1.hexdigest "#{password}#{user['salt']}"

  user = users.find_one({ :username => username, :password => computed_password })

  if user == nil
    return Error.new({ :error_code => INVALID_AUTH }).to_json
  end

  # Everything correct. Register and return session
  Success.new({ :session_id => Culturify.create_session(ddbb, username) }).to_json
end

delete '/api/session/:username/:session_id' do |username, session_id|
  # Connect to the private database
  ddbb = Culturify.private_ddbb

  sessions = ddbb['sessions']

  # Retrieve the specified session, and check if it belongs to the current user
  session = sessions.find_one({ :username => username, :session_id => session_id })

  if session == nil
    return Error.new({ :error_code => INVALID_USERNAME_OR_SESSION_ID }).to_json
  end

  sessions.remove({ :username => username })

  Success.new.to_json
end
