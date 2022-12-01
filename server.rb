require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements

set :port, 3000
set :bind, '0.0.0.0'

class GHAapp < Sinatra::Application

  # Converts the newlines. Expects that the private key has been set as an
  # environment variable in PEM format.
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Executed before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    case request.env['HTTP_X_GITHUB_EVENT']
    when 'issues'
      if @payload['action'] === 'opened'
        handle_issue_opened_event(@payload)
      end
      if @payload['action'] === 'edited'
        handle_issue_edited_event(@payload)
      end

      if @payload['action']=== 'reopened'
        handle_issue_reopened(@payload)
        parse_payload_for_user(@payload)
      end


        #Event handler for comments
      if @payload['action'] === 'comment'
        handle_comment_event(@payload) 
        parse_payload_for_user(@payload)
      end
      if @payload['action'] === 'closed'
        handle_comment_event(@payload) 
        parse_payload_for_user(@payload)
      end
    end

    200 # success status
  end


  helpers do

    #Will return the title of an issue webhook payload
    def get_issue_title(payload)
        title = payload["issue"]["title"]
    end

    #When a comment is created this will parse the payload and return the user
    def parse_payload_for_user(payload)
      result = JSON.parse(open(@payload))
      result.each do |key, value|
        puts "user[#{login}] = #{value}"
      end
    end

    def handle_issue_reopened(@payload)
      repo = payload['repository']['full_name']
      issue_number = payload['issue']['number']
      @installation_client.add_labels_to_an_issue(repo, issue_number, ['needs-response'])
    end
    # When there is a comment, grab username from the comment
    def handle_comment_event(payload)
      #grab the username from comment
      username = payload['comment']['user']['login']
      #grab the content from the comment
      content = payload['comment']['body']
    end

    # When an issue is opened, add a label
    def handle_issue_opened_event(payload)
      logger.debug 'An issue was created'
      repo = payload["repository"]["full_name"]
      number = payload["issue"]["number"]
      author = payload["issue"]["user"]["login"]
      content = payload['issue']['body']

      #From here down is just a test for now
      list = ["butt", "bafoon", "knave"]
      total = 20;
      message = message_to_user(author, list, total)
      #end of test

      #message = "Looks like @" + author + " posted a new issue. You better not say any dirty words.
      #You said \"" + content + "\" We've got our eye on you..."
      @installation_client.add_comment(repo, number, message)
    end

    # This method can be called when a swear is detected
    # When scanning the content for words that match the naughty_words.csv, store
    # the matching words into an array and pass them into this function as the
    # swearList parameter. 
    # @returns a long string to be sent as a message
    def message_to_user(username, swearList, total)
      message = "# Uh Oh! Naughty Detected! \nHey! That type of language can lead to"
      message += "negative outcomes such as depression, feelings of inadequacy, general contempt for humanity."
      message += "and in rare cases, rage-filled retaliation. To avoid these scenarios, we here at SwearJar"
      message += "suggest being a better person. To help incentivize this personal growth, we have increased"
      message += "your Swear Jar balance. \n### Username \n" + username + " needs some encouragement."
      message += " Let's go, " + username + "! Being a better person is just a few transactions away! \n"
      message += "### Naughties Detected \n"

      naughty_words = CSV.read('naughty.csv')
      h = naughty_words.to_h();

      swearList.each do |item|
        h.each do|key, value|
          if item == key
            message += item + " - $" + value + "\n"
          end
        end
      end

      message += "### Total in the Jar \n$" + total + "\n> You cannot do kindness too soon,"
      return message += "for you never know how soon it will be too late. -Ralph Waldo Emerson"
    end

    # When there is a comment, grab username from the comment
    def handle_comment_event(payload)
      #grab the username from comment
      username = payload['comment']['user']['login']
      #grab the content from the comment
      content = payload['comment']['body']
    end

    def parse_content(content, user)
      # Stores swearjar value for this content
      swearcount = 0

      naughty_words = CSV.read('naughty_words.csv')
      h = naughty_words.to_h()
      # iterate through hash array
      h.each do |key,value|
        swearcount += content.scan(/#{key}/).size * value.to_f
      end
      # Look at swearjar, search for user, and add swearcount to their amount owed
      from_file = YAML.load_file("swearjar.yml")
      # Translate to symbol for use in key
      k = user.to_sym
      # check if user already exists in swearjar
      if from_file.key?(k)
        # if true then add swearcount to already present value
        from_file[k] += swearcount
      else
        # If false add key and have swearcount be the new value
        from_file[k] = swearcount
      end

    end

    def handle_comment_event(payload)
      logger.debug payload
      repo = payload["repository"]["full_name"]
      number = payload["comment"]["number"]
      message ="hello world"
      @installation_client.add_comment(repo, number, message)
    end


    #read from file into instace var for hash
    def yaml_read_swearjar(from_file)
      from_file = YAML.load_file("swearjar.yml")
    end

    #writes passed hash to swearjar file
    def yaml_write_swearjar(hash)
      file.write('swearjar.yml', @hash.to_yaml)
    end

    # When an issue is opened, add a label
    def handle_issue_edited_event(payload)
      repo = payload['repository']['full_name']
      issue_number = payload['issue']['number']
      @installation_client.add_labels_to_an_issue(repo, issue_number, ['ignore'])
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app and was not altered by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
