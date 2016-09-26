#!/usr/bin/env python
#
# Copyright 2016 Greg Eastman
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#Natively provided by python libraries
import json
import logging

#Natively provided by app engine
import google.appengine.ext.ndb as ndb
import google.appengine.api.users as google_authentication
import google.appengine.api.mail

#Includes specified by the app.yaml
import webapp2
import webapp2_extras.auth

#App specific includes
import datamodel
import constants


_DEFAULT_MAX_RESULTS = 200
_DEFAULT_ROOT_KEY_NAME = datamodel.DEFAULT_ROOT_KEY_NAME

member_required = datamodel.member_required
free_text_to_safe_html_markup = datamodel.free_text_to_safe_html_markup
get_root_key = datamodel.get_root_key

def participant_required(handler):
    """
        Decorator that checks if there's a participant associated with the current page
        Will look to post and JSON for the participant.
    """
    def check_participant(self, *args, **kwargs):
        site_participant = self.get_participant(*args, **kwargs)
        if site_participant is None:
            self.redirect(self.uri_for('home'), abort=True)
        elif site_participant.is_valid_for_member(self.get_site_member()) == False:
            self.redirect(self.uri_for('home'), abort=True)
        else:    
            return handler(self, *args, **kwargs)      
    return check_participant

def send_email_helper(recipient_name, recipient_email, subject, plain_text_content): #, unsubscribe_link):
    """"Function that will sent an HTML email to a particular recipient with standard headers and footers"""
    plain_text = 'Hello ' + recipient_name + ',\n\n' + plain_text_content
    plain_text = plain_text + '\n\n\n-------------------------------------------------------------------------'
    plain_text = plain_text + '\nThis is an auto-generated email from Weekly Pick \'Em. Please do not reply to this email.'
    body = free_text_to_safe_html_markup(plain_text, 9999)
    #if unsubscribe_link:
    #    body = body + '<br /><a href="' + unsubscribe_link + '">Unsubscribe from automated updates</a>'
    #    plain_text = plain_text + '\nUnsubscribe: ' + unsubscribe_link
    
    message = google.appengine.api.mail.EmailMessage(
                sender='anonymous@spread-pickem.appspotmail.com',
                subject=subject)
    message.to = recipient_email
    message.body = plain_text
    message.html = '<html><head></head><body>' + body + '</body></html>'
    message.send()


class MainWebAppHandler(datamodel.BaseHandler):
    """A wrapper about webapp2.RequestHandler with customized methods"""
    def get_participant(self, *args, **kwargs):
        """Gets a participant from the headers"""
        contest_participant = None
        try:
            participant_string = kwargs['participant']
            participant_key = ndb.Key(urlsafe=participant_string)
            contest_participant = participant_key.get()
        except:
            pass
        return contest_participant
                           
class LoginHandler(MainWebAppHandler):
    """Class for handling logins"""
    def get(self):
        """Handles the get requests for logins"""
        site_member = self.get_site_member()
        if site_member:
            self.redirect(self.uri_for('home'))
            return
        self.render_template('login.html')

    def post(self):
        """Process the login request as a forms post"""
        username = self.request.get('username')
        password = self.request.get('password')
        failure_message = 'Username/password was not found'
        try:
            self.auth.get_user_by_password(username, password, remember=True, save_session=True)
            self.redirect(self.uri_for('home'))
            return
        except (webapp2_extras.auth.InvalidAuthIdError, webapp2_extras.auth.InvalidPasswordError) as e:
            logging.info('Login failed for user %s because of %s', username, type(e))
        if username.find('@') != -1:
            root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
            member = datamodel.SiteMember.get_member_by_email(root_key, username)
            if member is not None and member.verified_email and member.user_key:
                login_string = member.user_key.get().auth_ids[0]
                try:
                    self.auth.get_user_by_password(login_string, password, remember=True, save_session=True)
                    self.redirect(self.uri_for('home'))
                    return
                except (webapp2_extras.auth.InvalidAuthIdError, webapp2_extras.auth.InvalidPasswordError) as e:
                    logging.info('Login failed for user %s because of %s', login_string, type(e))
        self.add_template_values({'username': username, 'failure_message': failure_message})
        self.render_template('login.html')

class GoogleLoginHandler(MainWebAppHandler):
    """Class for handling logins that simply requires google authentication before proceeding"""
    def get(self, *args, **kwargs):
        """Get method for google authentication login. Should be a passthrough, but
             handles the scenario where an account is not yet created"""
        if self.get_site_member(*args, **kwargs):
            self.redirect(self.uri_for('home'))
            return
        failure_message = 'Could not find user for ' + google_authentication.get_current_user().email() + '. You must create an account first.'
        self.add_template_values({'failure_message': failure_message, 'google_logout': google_authentication.create_logout_url(self.uri_for('login'))})
        self.render_template('login.html')

class LogoutHandler(MainWebAppHandler):
    """Handles get requests for logging out"""
    def get(self):
        """Logs a user out. Checks if the user is logged in natively and logs them out, otherwise will log
            them out of google"""
        auth = self.auth
        session_user = auth.get_user_by_session()
        user_object = None
        if session_user:
            try:
                user_object = datamodel.User.get_by_id(session_user['user_id'])
            except:
                pass
        if user_object:
            self.auth.unset_session()
        else:
            self.redirect(google_authentication.create_logout_url(self.uri_for('login')))
            return        
        self.redirect(self.uri_for('login'))

class SignupHandler(MainWebAppHandler):
    """Class for processing new user signup"""
    def get(self):
        """Handles get requests for signing up"""
        google_user = google_authentication.get_current_user()
        default_native = True
        if google_user:
            default_native = False
        template_values = {
                'google_user': google_user,
                'default_native': default_native,
                'google_login_url': google_authentication.create_login_url(self.uri_for('signup'))
            }
        self.add_template_values(template_values)
        self.render_template('signup.html')
    
    def post(self):
        """Handles creating new users"""
        data = json.loads(self.request.body)
        
        account_type = data['account_type']
        
        name = data['name']
        lastname = data['lastname']
        if not name:
            self.response.out.write(json.dumps(({'message': 'Name is required.'})))
            return
        if not lastname:
            self.response.out.write(json.dumps(({'message': 'Last name is required.'})))
            return
        root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
    
        if account_type == 'native':
            user_name = data['username']
            email = data['email']
            password = data['password']
            if not user_name:
                self.response.out.write(json.dumps(({'message': 'Username is required.'})))
                return
            if not password:
                self.response.out.write(json.dumps(({'message': 'Password is required.'})))
                return
            if not email:
                self.response.out.write(json.dumps(({'message': 'Email is required.'})))
                return
            email_object = None
            try:
                email_object = datamodel.UserUnique.create_unique_value('email', email)
            except:
                email_object = None
            if not email_object:
                self.response.out.write(json.dumps(({'message': 'Email address already exists'})))
                return
            user_data = self.user_model.create_user(user_name, name=name, password_raw=password)
            if not user_data[0]: #user_data is a tuple
                msg = ''
                if 'auth_id' in user_data[1]:
                    msg = 'Username already exists: ' + user_name
                email_object.key.delete() #clean up object
                self.response.out.write(json.dumps(({'message': msg})))
                return
            
            user = user_data[1]
            user_id = user.get_id()
            
            datamodel.SiteMember.create_member_by_native_user(root_key, user, email_object, name, lastname)
            
            token = self.user_model.create_signup_token(user_id)
        
            verification_url = self.uri_for('verification', type='v', user_id=user_id,
              signup_token=token, _full=True)
        
            message_content = 'You have signed up for a new account at Weekly Pick \'Em: ' + self.uri_for('root')
            message_content = message_content + 'Verify your account at ' + verification_url
            send_email_helper(name, email, 'Account Verification for Weekly Pick \'Em', message_content, None)
            self.response.out.write(json.dumps(({'message': ''})))
            return
        elif account_type == 'google':
            google_user = google_authentication.get_current_user()
            if google_user is None:
                self.response.out.write(json.dumps(({'message': 'Cannot create google user when not logged in.'})))
                return
            google_user_object = None
            try:
                google_user_object = datamodel.UserUnique.create_unique_value('google', google_user.user_id())
            except:
                google_user_object = None
            if not google_user_object:
                self.response.out.write(json.dumps(({'message': 'User already exists with this account.'})))
                return
            datamodel.SiteMember.create_member_by_google_user(root_key, google_user_object, name, lastname, google_user.email())
            self.response.out.write(json.dumps(({'message': ''})))
            return
        self.response.out.write(json.dumps(({'message': 'Unknown error'})))
        
        
class VerificationHandler(MainWebAppHandler):
    """Verification handler used for verifiying emails and handling forgotten passwords"""
    def get(self, *args, **kwargs):
        """Handles get requests for verifying emails and forgotten passwords"""
        user = None
        user_id = kwargs['user_id']
        signup_token = kwargs['signup_token']
        verification_type = kwargs['type']
    
        # it should be something more concise like
        # self.auth.get_user_by_token(user_id, signup_token)
        # unfortunately the auth interface does not (yet) allow to manipulate
        # signup tokens concisely 
        my_tuple = self.user_model.get_by_auth_token(int(user_id), signup_token,
          'signup')
        
        if my_tuple:
            user = my_tuple[0]
        if not user:
            logging.info('Could not find any user with id "%s" signup token "%s"',
                         user_id, signup_token)
            self.abort(404)
        
        # store user data in the session
        self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
    
        if verification_type == 'v':
            # remove signup token, we don't want users to come back with an old link
            self.user_model.delete_signup_token(user.get_id(), signup_token)
            
            root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
            member = datamodel.SiteMember.get_member_by_user_key(root_key, user.key)
            member.verify_email_address()
            self.render_template('verification.html')
            return
        elif verification_type == 'p':
            # remove signup token, we don't want users to come back with an old link
            # this is pretty aggressive to remove it immediately, since it means the user can't refresh the page
            # but it's easy to request a new link
            self.user_model.delete_signup_token(user.get_id(), signup_token)
            
            # supply user to the page
            self.add_template_values({'user': user})
            self.render_template('setpassword.html')
        else:
            logging.info('verification type not supported')
            self.abort(404)

class SetPasswordHandler(MainWebAppHandler):
    """Class for setting a user's password."""
    @member_required
    def get(self):
        # supply user to the page
        self.add_template_values({'user': self.user})
        self.render_template('setpassword.html')
    
    @member_required
    def post(self):
        """Handles the request to set a user's password"""
        data = json.loads(self.request.body)
        password = data['password']
        if not password or password != data['confirm_password']:
            self.response.out.write(json.dumps(({'message': 'Passwords do not match'})))
            return
        user = self.user
        user.set_password(password)
        user.put()
        self.response.out.write(json.dumps(({'message': ''})))


class ForgotPasswordHandler(MainWebAppHandler):
    """Class for handling a forgotten password."""
    def get(self):
        """Handles the front-end for a user requesting a forgotten password."""
        self.render_template('forgot.html')

    def post(self):
        """Handles the request for a user forgetting their password and send an email with verification"""
        data = json.loads(self.request.body)
        username = data['username']
        user = self.user_model.get_by_auth_id(username)
        if not user:
            msg = 'Could not find any user entry for username %s', username
            logging.info(msg)
            self.response.out.write(json.dumps(({'message': msg})))
            return
    
        user_id = user.get_id()
        token = self.user_model.create_signup_token(user_id)
    
        verification_url = self.uri_for('verification', type='p', user_id=user_id,
          signup_token=token, _full=True)
    
        message_content = 'You have signed up for a new account at Weekly Pick \'Em: ' + self.uri_for('root')
        message_content = message_content + 'Verify your account at ' + verification_url
        root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
        member = datamodel.SiteMember.get_member_by_user_key(root_key, user.key)
        send_email_helper(member.first_name, member.get_email_address(), 'Password Reset for Weekly Pick \'Em', message_content, None)
        self.response.out.write(json.dumps(({'message': ''})))

class PreferencesHandler(MainWebAppHandler):
    """The handler for updating preferences."""
    @member_required
    def get(self):
        """Handles get requests and serves up the preference page."""
        member = self.get_site_member()
        template_values = {
                           'page_title': 'User Preferences',
                           'google_user': google_authentication.get_current_user(),
                           'google_login_url': google_authentication.create_login_url(self.uri_for('preferences')),
                           'member': member,
                        }
        self.add_template_values(template_values)
        self.render_template('preferences.html')
    
    @member_required
    def post(self):
        """Handles posts requests for updating preferences. Requires a JSON object."""
        refresh = ''
        data = json.loads(self.request.body)
        member_is_dirty = False
        member = self.get_site_member()
        first_name = data['name']
        last_name = data['lastname']
        email = data['email']
        if not first_name:
            self.response.out.write(json.dumps(({'message': 'First name cannot be blank'})))
            return
        if not last_name:
            self.response.out.write(json.dumps(({'message': 'Last name cannot be blank'})))
            return
        if not email:
            self.response.out.write(json.dumps(({'message': 'Email cannot be blank'})))
            return
        email_object = None
        if (member.get_email_address() != email) or (member.pending_email_key is not None):
            #The UI doesn't allow a change, but if the user is a google user, this can temporarily change the email
            #That doesn't really matter, since it will be reset    
            if member.get_email_address() != email:
                #This is also slightly weird when there's a pending email change, but that should be unlikely, and the behavior is not "wrong"
                #If I keep the existing address, it will clear the pending update
                #If I change to pending address, it will throw an error
                #If I put in a new address, it will work as expected
                try:
                    email_object = datamodel.UserUnique.create_unique_value('email', email)
                except:
                    email_object = None
                if email_object is None:
                    self.response.out.write(json.dumps(({'message': 'Email is already in use'})))
                    return
            else:
                refresh = '1' #if updating with pending email, simply clear out pending key
            #clean up old pending key
            if member.pending_email_key:
                member.pending_email_key.get().key.delete()
                member.pending_email_key = None
                member_is_dirty = True
        if member.first_name != first_name:
            member.first_name = first_name
            member_is_dirty = True
            try:
                user_object = member.user_key.get()
                user_object.name = first_name
                user_object.put()
            except:
                pass
        if member.last_name != last_name:
            member.last_name = last_name
            member_is_dirty =True
        if email_object is not None:
            member.pending_email_key = email_object.key
            member_is_dirty = True
            user_id = member.user_key.id()
            refresh = '1'
            token = self.user_model.create_signup_token(user_id)
        
            verification_url = self.uri_for('verification', type='v', user_id=user_id,
              signup_token=token, _full=True)
        
            message_content = 'You have updated your email at Weekly Pick \'Em: ' + self.uri_for('root')
            message_content = message_content + 'Verify your email address at ' + verification_url
            send_email_helper(member.first_name, email, 'Email Verification for Weekly Pick \'Em', message_content, None)
            
        if member_is_dirty:
            member.put()
        self.response.out.write(json.dumps(({'message': '', 'refresh': refresh})))

class GoogleLinkHandler(MainWebAppHandler):
    """Class for handling linking and unlinking google accounts"""
    @member_required
    def post(self, *args, **kwargs):
        """Handles the request to link or unlink a google account from a member"""
        data = json.loads(self.request.body)
        change_type = data['type']
        member = self.get_site_member(*args, **kwargs)
        if change_type == 'link':
            google_user = google_authentication.get_current_user()
            if not google_user:
                self.response.write(json.dumps(({'message': 'Must be logged into Google to link account.'})))
                return
            google_user_object = None
            try:
                google_user_object = datamodel.UserUnique.create_unique_value('google', google_user.user_id())
            except:
                google_user_object = None
            if not google_user_object:
                self.response.out.write(json.dumps(({'message': 'Cannot link Google account because it is already linked to another user.'})))
                return
            member.link_google_user(google_user_object)
            self.response.write(json.dumps(({'message': ''})))
            return
        elif change_type == 'unlink':
            if member.user_key is None:
                self.response.write(json.dumps(({'message': 'Cannot unlink google account if there is no native user.'})))
                return
            member.unlink_google_user()
            self.response.write(json.dumps(({'message': ''})))
            return
        self.response.write(json.dumps(({'message': 'Unsupported command'})))

class HomeHandler(MainWebAppHandler):
    """The home page of the weekly pickem app. This finds any events that a member is in"""
    @member_required
    def get(self):
        """The handler for get requests to the home page"""
        root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
        member = self.get_site_member()
        all_participants = []
        if member is not None:
            query = datamodel.ContestParticipant.get_participants_by_member_query(root_key, member.key)
            all_participants = query.fetch(_DEFAULT_MAX_RESULTS)
        participant_list = []
        for participant in all_participants:
            if participant.get_contest().is_active():
                participant_list.append(participant)
        if len(participant_list)==1:
            participant = participant_list[0]
            self.redirect(self.uri_for('main', participant=participant.key.urlsafe()))
        else:
            self.add_template_values({'participant_list': participant_list })
            self.render_template('home.html')
        return

class MainHandler(MainWebAppHandler):
    """The main page for a given event. Requires a specific participant"""
    @member_required
    @participant_required
    def get(self, *args, **kwargs):
        """Handles get requests for the main page of a given event."""
        #contest_participant = self.get_participant(*args, **kwargs)
        #root_key = get_root_key(_DEFAULT_ROOT_KEY_NAME)
        template_values = {
                
            }
        self.add_template_values(template_values)
        self.render_template('main.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'datamodel.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': constants.SECRET_KEY
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=LoginHandler, name='root'),
    webapp2.Route('/login', handler=LoginHandler, name='login'),
    webapp2.Route('/googlelogin', GoogleLoginHandler),
    webapp2.Route('/logout', handler=LogoutHandler, name='logout'),
    webapp2.Route('/signup', handler=SignupHandler, name='signup'),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/forgot', handler=ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/link', GoogleLinkHandler),
    webapp2.Route('/home', handler=HomeHandler, name='home'),
    webapp2.Route('/main/<participant:.+>', handler=MainHandler, name='main'),
    webapp2.Route('/preferences', handler=PreferencesHandler, name='preferences'),
], debug=False, config=config)

logging.getLogger().setLevel(logging.DEBUG)
