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
import os
import time
import re

#Natively provided by app engine
import google.appengine.ext.ndb as ndb
import google.appengine.api.users as google_authentication

#Includes specified by the app.yaml
import webapp2
import jinja2
import webapp2_extras.auth
import webapp2_extras.sessions
import webapp2_extras.appengine.auth.models
import webapp2_extras.security

#Included third party libraries distributed with the project
import bleach

#constants
DEFAULT_ROOT_KEY_NAME = 'playground'
_urlfinderregex = re.compile(r'http([^\.\s]+\.[^\.\s]*)+[^\.\s]{2,}')

_JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

def member_required(handler):
    """
        Decorator that checks if there's a member associated with the current session.
        Will also fail if there's no session present.
    """
    def check_login(self, *args, **kwargs):
        if not self.get_site_member():
            self.redirect(self.uri_for('login'), abort=True)
        else:
            return handler(self, *args, **kwargs)
    return check_login

def get_root_key(root_key_name):
    """Returns the default key that all data is stored under"""
    return ndb.Key('SpreadPicks', root_key_name)

def free_text_to_safe_html_markup(text, max_link_length):
    """Takes a string of user entered text and converts it to html, with a minimal amount of safe markup
        :param text:
            The string of user entered text
        :param max_link_length:
            The maximum length of a url. If longer, it will be truncated
        :returns:
            A string of HTML
        """
    def replace_with_link(matchobj):
        url = matchobj.group(0)
        text = unicode(url)
        if text.startswith('http://'):
            text = text.replace('http://', '', 1)
        elif text.startswith('https://'):
            text = text.replace('https://', '', 1)

        if text.startswith('www.'):
            text = text.replace('www.', '', 1)

        if len(text) > max_link_length:
            half_length = max_link_length / 2
            text = text[0:half_length] + '...' + text[len(text) - half_length:]

        return '<a class="comurl" href="' + url + '" target="_blank" rel="nofollow">' + text + '<img class="imglink" src="/media/images/linkout.png"></a>'

    if text != None and text != '':
        text = bleach.clean(text)
        text = _urlfinderregex.sub(replace_with_link, text)
        return text.replace('\n', '<br />')
    return ''

class BaseHandler(webapp2.RequestHandler):
    """A wrapper about webapp2.RequestHandler with customized methods"""
    def __init__(self, *args, **kwargs):
        super(BaseHandler, self).__init__(*args, **kwargs)
        self._my_templates = {}
        self._my_templates['page_title'] =  'Weekly Pick\'Em' #set default page title
        self._my_templates['logout_url'] = '/logout'
        self._my_templates['logged_in_member'] = self.get_site_member()
    
    def add_template_values(self, template_values):
        """Adds a list of templates to the array"""
        for key in template_values:
            self._my_templates[key] = template_values[key]
        return
    
    def render_template(self, template):
        """Renders a remplate with the built up list of values"""
        self.response.write(_JINJA_ENVIRONMENT.get_template(template).render(self._my_templates))
        
    @webapp2.cached_property
    def auth(self):
        """Shortcut to access the auth instance as a property."""
        return webapp2_extras.auth.get_auth()
    
    @webapp2.cached_property
    def user_info(self):
        """Shortcut to access a subset of the user attributes that are stored
        in the session.

        The list of attributes to store in the session is specified in
          config['webapp2_extras.auth']['user_attributes'].
        :returns
          A dictionary with most user information
        """
        return self.auth.get_user_by_session()

    @webapp2.cached_property
    def user(self):
        """Shortcut to access the current logged in user.

        Unlike user_info, it fetches information from the persistence layer and
        returns an instance of the underlying model.

        :returns
          The instance of the user model associated to the logged in user.
        """
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None

    @webapp2.cached_property
    def user_model(self):
        """Returns the implementation of the user model.

        It is consistent with config['webapp2_extras.auth']['user_model'], if set.
        """    
        return self.auth.store.user_model

    @webapp2.cached_property
    def session(self):
        """Shortcut to access the current session."""
        return self.session_store.get_session(backend="datastore")
    
    # this is needed for webapp2 sessions to work
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = webapp2_extras.sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    def get_site_member(self):
        """Gets the member object associated with a particular session"""
        site_member = None
        root_key = get_root_key(DEFAULT_ROOT_KEY_NAME)
        #first see if the user is in the DB
        auth = self.auth
        session_user = auth.get_user_by_session()
        if session_user:
            try:
                user_object = User.get_by_id(session_user['user_id'])
                site_member = SiteMember.get_member_by_user_key(root_key, user_object.key)
            except:
                pass
        if site_member is None:
            try:
                google_user = google_authentication.get_current_user()      
                site_member = SiteMember.update_and_retrieve_member_by_google_user(root_key, google_user)
            except:
                pass
        return site_member

class User(webapp2_extras.appengine.auth.models.User):
    """Class for extending the user model to allow local authentication"""
    def set_password(self, raw_password):
        """Sets the password for the current user

        :param raw_password:
            The raw password which will be hashed and stored
        """
        self.password = webapp2_extras.security.generate_password_hash(raw_password, length=12)

    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
        """Returns a user object based on a user ID and token.

        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
        """
        token_key = cls.token_model.get_key(user_id, subject, token)
        user_key = ndb.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = ndb.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp
        return None, None

class UserUnique(ndb.Model):
    property_type = ndb.StringProperty(indexed=False)
    property_value = ndb.StringProperty(indexed=False)
    
    @staticmethod
    @ndb.transactional
    def create_unique_value(value_type, value):
        key_string = ndb.Key(UserUnique, value_type + ":" + value)
        if key_string.get():
            return None
        unique_object = UserUnique(key=key_string, property_type=value_type, property_value=value)
        unique_object.put()
        return unique_object

class SiteMember(ndb.Model):
    """A person that could be used in anonymous giving sessions"""
    google_user_key = ndb.KeyProperty(indexed=True, kind=UserUnique)
    google_user_id = ndb.StringProperty(indexed=True)
    first_name = ndb.StringProperty(indexed=False)
    last_name = ndb.StringProperty(indexed=False)
    user_key = ndb.KeyProperty(indexed=True, kind=User)
    
    #This represents the address to send to. It's the verified email if there is one
    #If there is no native user, it's the google email
    #If the user hasn't verified their initial email, it will still be set
    email_address = ndb.StringProperty(indexed=True)
    email_key = ndb.KeyProperty(indexed=True, kind=UserUnique)
    pending_email_key = ndb.KeyProperty(indexed=True, kind=UserUnique)
    verified_email = ndb.BooleanProperty(indexed=False, default=False)
    
    def get_email_address(self):
        """Returns the member's email address"""
        return self.email_address
    
    def verify_email_address(self):
        """Verifies a user's email address"""
        if self.pending_email_key:
            old_email_object_key = self.email_key
            if old_email_object_key:
                old_email_object_key.get().key.delete()
            self.email_key = self.pending_email_key
            self.pending_email_key = None
            self.email_address = self.email_key.get().property_value
            self.verified_email = True
            self.put()
        return
    
    def link_google_user(self, google_user_object):
        """Links a member to a particular google account"""
        self.google_user_key = google_user_object.key
        self.google_user_id = google_user_object.property_value
        self.put()
    
    def unlink_google_user(self):
        """Deletes the link to a particular google account"""
        #Consider verifying that there's a native user
        google_user_object_key = self.google_user_key
        if google_user_object_key:
            google_user_object_key.get().key.delete()
        self.google_user_key = None
        self.google_user_id = None
        self.put()
    
    @staticmethod
    def get_member_by_user_key(root_key, user_key):
        """Gets a member by their user record"""   
        query = SiteMember.query(SiteMember.user_key==user_key, ancestor=root_key)
        return query.get()
    
    @staticmethod
    def get_member_by_google_id(root_key, google_user_id):
        """Returns a user by their google user id. Will return none if the user doesn't exist"""
        query = SiteMember.query(SiteMember.google_user_id==google_user_id, ancestor=root_key)
        return query.get()
    
    @staticmethod
    def create_member_by_native_user(root_key, user, email_object, first_name, last_name):
        """Create a member based off a native user account"""
        member = SiteMember.get_member_by_user_key(root_key, user.key)
        if member is None:
            member = SiteMember(parent=root_key, 
                                        user_key=user.key,
                                        first_name=first_name,
                                        last_name=last_name, 
                                        pending_email_key=email_object.key,
                                        email_address = email_object.property_value)
            member.put()
        return member
    
    @staticmethod
    def create_member_by_google_user(root_key, google_user_object, first_name, last_name, email):
        """Create a member based off a google account and some minimal extra information"""
        member = SiteMember.get_member_by_google_id(root_key, google_user_object.property_value)
        #Consider validating google_user and google_user_object aren't null
        if member is None:
            member = SiteMember(parent=root_key, 
                                        google_user_id=google_user_object.property_value,
                                        google_user_key=google_user_object.key,
                                        first_name=first_name,
                                        last_name=last_name, 
                                        email_address=email,
                                        verified_email=True)
            member.put()
        return member
    
    @staticmethod
    def update_and_retrieve_member_by_google_user(root_key, google_user):
        """Gets a member by their google user id. If the cache is out of date, it will update it.
                It will not create any users"""
        member = SiteMember.get_member_by_google_id(root_key, google_user.user_id())
        if member is not None:
            if member.user_key is None: #only update email address if google is the only source
                if member.email_address != google_user.email():
                    member.email_address = google_user.email()
                    member.put()
        return member
    
    @staticmethod
    def get_member_by_email(root_key, email):
        """Gets a member by their email address. References to emails shouldn't be stored, but are
            useful for display in UIs, so it should only be for using as a public facing intermediary"""
        query = SiteMember.query(SiteMember.email_address==email, ancestor=root_key)
        return query.get()
    
    @staticmethod
    def get_all_members_query(root_key):
        """Returns a query for getting all possible members of the system"""
        return SiteMember.query(ancestor=root_key)

class PicksGame(ndb.Model):
    home_team = ndb.StringProperty(indexed=False)
    away_team = ndb.StringProperty(indexed=False)
    spread = ndb.IntegerProperty(indexed=False)
    home_team_points = ndb.IntegerProperty(indexed=False)
    away_team_points = ndb.IntegerProperty(indexed=False)
    home_team_won_spread = ndb.BooleanProperty(indexed=False)

class PicksWeek(ndb.Model):
    week_number = ndb.IntegerProperty(indexed=False)
    games_keys = ndb.KeyProperty(indexed=False, kind=PicksGame, repeated=True)

class PicksContest(ndb.Model):
    """An event for anonymous giving"""
    display_name = ndb.StringProperty(indexed=False)
    has_started = ndb.BooleanProperty(indexed=False, default=False)
    has_ended = ndb.BooleanProperty(indexed=False, default=False)
    weeks_keys = ndb.KeyProperty(indexed=False, kind=PicksWeek, repeated=True)
    
    def is_active(self):
        """Returns whether an event is active"""
        return (self.has_started and not self.has_ended)
    
    @staticmethod
    def get_all_contests_query(root_key):
        """Returns a query that will return all events"""
        return PicksContest.query(ancestor=root_key)

class ContestParticipant(ndb.Model):
    """A particular instantiation of a member in a giving event"""
    member_key = ndb.KeyProperty(indexed=True, kind=SiteMember)
    display_name = ndb.StringProperty(indexed=False)
    contest_key = ndb.KeyProperty(indexed=True, kind=PicksContest)
    
    def get_contest(self):
        """Returns the event object that a member is in"""
        return self.contest_key.get()
    
    def get_member(self):
        """Returns the member object for this participant"""
        return self.member_key.get()
    
    def is_valid_for_member(self, site_member):
        """Determines where a participant matches a particular member"""
        participant_member = self.member_key.get()
        return (participant_member.key == site_member.key)
        
    @staticmethod
    def get_participants_in_contest_query(root_key, contest_key):
        """Returns a query for gathering all participants in an event"""
        return ContestParticipant.query(ContestParticipant.contestt_key==contest_key, ancestor=root_key)
    
    @staticmethod
    def get_participants_by_member_query(root_key, member_key):
        """Gets the list of participants for a particular member"""
        #Ideally this would query the event's status. Computed properties don't seem to be a perfect fit since
        #they are updated upon put, and not all the participants are updated upon the starting/ending of events
        return ContestParticipant.query(ContestParticipant.member_key==member_key, ancestor=root_key)

class IndividualPick(ndb.Model):
    game_key = ndb.KeyProperty(indexed=True, kind=PicksGame)
    pick_value = ndb.IntegerProperty(default=0) #make integer so it can handle the tri-state of home/away/no-pick
    confidence = ndb.IntegerProperty(indexed=False)
    is_pick_correct = ndb.BooleanProperty(default=False)
    
class ParticipantsPicks(ndb.Model):
    participant_key = ndb.KeyProperty(indexed=False, kind=ContestParticipant)
    week_key = ndb.KeyProperty(indexed=False, kind=PicksWeek)
    picks_keys = ndb.KeyProperty(indexed=False, kind=IndividualPick, repeated=True)