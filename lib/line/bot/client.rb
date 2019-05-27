# Copyright 2016 LINE
#
# LINE Corporation licenses this file to you under the Apache License,
# version 2.0 (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

require 'line/bot/api/errors'
require 'base64'
require 'net/http'
require 'openssl'

module Line
  module Bot
    class Client
      #  @return [String]
      attr_accessor :channel_token, :channel_secret, :endpoint

      # @return [Object]
      attr_accessor :httpclient

      # @return [Hash]
      attr_accessor :http_options

      # Initialize a new Bot Client.
      #
      # @param options [Hash]
      #
      # @return [Line::Bot::Client]
      def initialize(options = {})
        options.each do |key, value|
          instance_variable_set("@#{key}", value)
        end
        yield(self) if block_given?
      end

      def httpclient
        @httpclient ||= Line::Bot::HTTPClient.new(
          http_options: http_options,
          default_headers: {
            'User-Agent' => "LINE-BotSDK-Ruby/#{Line::Bot::API::VERSION}",
            'Authorization' => "Bearer #{channel_token}",
          }
        )
      end

      def endpoint
        @endpoint ||= Line::Bot::API::DEFAULT_ENDPOINT
      end

      # Push messages to line server and to user.
      #
      # @param user_id [String] User's identifiers
      # @param messages [Hash or Array]
      #
      # @return [Net::HTTPResponse]
      def push_message(user_id, messages)
        httpclient.post_json("#{endpoint}/bot/message/push", {
          to: user_id,
          messages: ensure_array(messages)
        })
      end

      # Reply messages to line server and to users.
      #
      # @param token [String]
      # @param messages [Hash or Array]
      #
      # @return [Net::HTTPResponse]
      def reply_message(token, messages)
        httpclient.post_json("#{endpoint}/bot/message/reply", {
          replyToken: token,
          messages: ensure_array(messages)
        })
      end

      def multicast_message(user_ids, messages)
        httpclient.post_json("#{endpoint}/bot/message/multicast", {
          to: ensure_array(user_ids),
          messages: ensure_array(messages)
        })
      end

      def broadcast_message(messages)
        httpclient.post_json("#{endpoint}/bot/message/broadcast", {
          messages: ensure_array(messages)
        })
      end

      # Broadcast messages to users
      #
      # @param messages [Hash or Array]
      #
      # @return [Net::HTTPResponse]
      def broadcast(messages)
        raise Line::Bot::API::InvalidCredentialsError, 'Invalidates credentials' unless credentials?

        messages = [messages] if messages.is_a?(Hash)

        request = Request.new do |config|
          config.httpclient     = httpclient
          config.endpoint       = endpoint
          config.endpoint_path  = '/bot/message/broadcast'
          config.credentials    = credentials
          config.messages       = messages
        end

        request.post
      end

      def leave_group(group_id)
        httpclient.post_json("#{endpoint}/bot/group/#{group_id}/leave", '')
      end

      def leave_room(room_id)
        httpclient.post_json("#{endpoint}/bot/room/#{room_id}/leave", '')
      end

      def get_message_content(identifier)
        httpclient.get("#{endpoint}/bot/message/#{identifier}/content")
      end

      def get_profile(user_id)
        httpclient.get("#{endpoint}/bot/profile/#{user_id}")
      end

      def get_group_member_profile(group_id, user_id)
        httpclient.get("#{endpoint}/bot/group/#{group_id}/member/#{user_id}")
      end

      def get_room_member_profile(room_id, user_id)
        httpclient.get("#{endpoint}/bot/room/#{room_id}/member/#{user_id}")
      end

      def get_group_member_ids(group_id, continuation_token = nil)
        query = {}
        query['start'] = continuation_token if continuation_token
        httpclient.get("#{endpoint}/bot/group/#{group_id}/members/ids", query: query)
      end

      def get_room_member_ids(room_id, continuation_token = nil)
        query = {}
        query['start'] = continuation_token if continuation_token
        httpclient.get("#{endpoint}/bot/room/#{room_id}/members/ids", query: query)
      end

      def get_rich_menus
        httpclient.get("#{endpoint}/bot/richmenu/list")
      end

      def get_rich_menu(rich_menu_id)
        httpclient.get("#{endpoint}/bot/richmenu/#{rich_menu_id}")
      end

      def get_message_delivery_reply(date)
        httpclient.get("#{endpoint}/bot/message/delivery/reply", query: {date: date})
      end

      def get_message_delivery_push(date)
        httpclient.get("#{endpoint}/bot/message/delivery/push", query: {date: date})
      end

      def get_message_delivery_multicast(date)
        httpclient.get("#{endpoint}/bot/message/delivery/multicast", query: {date: date})
      end

      def get_message_delivery_broadcast(date)
        httpclient.get("#{endpoint}/bot/message/delivery/broadcast", query: {date: date})
      end

      def create_rich_menu(rich_menu)
        httpclient.post_json("#{endpoint}/bot/richmenu", rich_menu)
      end

      def delete_rich_menu(rich_menu_id)
        httpclient.delete("#{endpoint}/bot/richmenu/#{rich_menu_id}")
      end

      # TODO: get_user_rich_menu ~ get_rich_menu_image

      def create_rich_menu_image(rich_menu_id, file)
        httpclient.post_file("#{endpoint}/bot/richmenu/#{rich_menu_id}/content", file)
      end

      # TODO: create_link_token

      # Get the target limit for additional messages
      #
      # @return [Net::HTTPResponse]
      def get_quota
        endpoint_path = "/bot/message/quota"
        get(endpoint_path)
      end

      # Get number of messages sent this month
      #
      # @return [Net::HTTPResponse]
      def get_quota_consumption
        endpoint_path = "/bot/message/quota/consumption"
        get(endpoint_path)
      end

      # Fetch data, get content of specified URL.
      #
      # @param endpoint_path [String]
      #
      # @return [Net::HTTPResponse]
      def get(endpoint_path, query: {}, header: {})
        httpclient.get("#{endpoint}#{endpoint_path}", query: query, header: header)
      end

      # Post data, get content of specified URL.
      #
      # @param endpoint_path [String]
      #
      # @return [Net::HTTPResponse]
      def post(endpoint_path, payload = nil, query: {}, header: {})
        httpclient.post_json("#{endpoint}#{endpoint_path}", payload, query: query, header: header)
      end

      # Delete content of specified URL.
      #
      # @param endpoint_path [String]
      #
      # @return [Net::HTTPResponse]
      def delete(endpoint_path, query: {}, header: {})
        httpclient.delete("#{endpoint}#{endpoint_path}", query: query, header: header)
      end

      # Parse events from request.body
      #
      # @param request_body [String]
      #
      # @return [Array<Line::Bot::Event::Class>]
      def parse_events_from(request_body)
        json = JSON.parse(request_body)

        json['events'].map do |item|
          begin
            klass = Line::Bot::Event.const_get(Line::Bot::Util.camelize(item['type']))
            klass.new(item)
          rescue NameError
            Line::Bot::Event::Base.new(item)
          end
        end
      end

      # Validate signature
      #
      # @param content [String] Request's body
      # @param channel_signature [String] Request'header 'X-LINE-Signature' # HTTP_X_LINE_SIGNATURE
      #
      # @return [Boolean]
      def validate_signature(content, channel_signature)
        return false if !channel_signature || !channel_secret

        hash = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, channel_secret, content)
        signature = Base64.strict_encode64(hash)

        variable_secure_compare(channel_signature, signature)
      end

      private

      # Constant time string comparison.
      #
      # via timing attacks.
      # reference: https://github.com/rails/rails/blob/master/activesupport/lib/active_support/security_utils.rb
      # @return [Boolean]
      def variable_secure_compare(a, b)
        secure_compare(::Digest::SHA256.hexdigest(a), ::Digest::SHA256.hexdigest(b))
      end

      # @return [Boolean]
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        l = a.unpack "C#{a.bytesize}"

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
      end

      def ensure_array(array_or_hash)
        array_or_hash.is_a?(Array) ? array_or_hash : [array_or_hash]
      end
    end
  end
end
