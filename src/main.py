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

import webapp2

class LoginHandler(webapp2.RequestHandler):
    """Class for handling logins"""
    def get(self):
        """Handles the get requests for logins"""
        self.response.out.write("""
            <html>
                <head><title>placeholder</title></head>
                <body>
                    <span>to be implemented</span>
                </body>
            </html>""")

app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=LoginHandler, name='root'),
], debug=False)
