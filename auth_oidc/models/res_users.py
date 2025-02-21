# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

import requests

from odoo import api, models
from odoo.exceptions import AccessDenied
from odoo.fields import Command
from odoo.http import request

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    def _auth_oauth_get_tokens_implicit_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        return params.get("access_token"), params.get("id_token")

    def _auth_oauth_get_tokens_auth_code_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        auth = None
        if oauth_provider.client_secret:
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        response = requests.post(
            oauth_provider.token_endpoint,
            data=dict(
                client_id=oauth_provider.client_id,
                grant_type="authorization_code",
                code=code,
                code_verifier=oauth_provider.code_verifier,  # PKCE
                redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
            ),
            auth=auth,
            timeout=10,
        )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        return response_json.get("access_token"), response_json.get("id_token")

    @api.model
    def _auth_oauth_validate(self, provider, id_token, access_token):
        """
        return the validation data corresponding to the access token
        Mostly the same as auth_oauth ResUsers._auth_oauth_validate, minus the
        validation_endpoint
        """
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)

        # Parse the token to get validation data
        validation = oauth_provider._parse_id_token(id_token, access_token)

        if oauth_provider.data_endpoint:
            data = super()._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
            validation.update(data)
        # unify subject key, pop all possible and get most sensible. When this
        # is reworked, BC should be dropped and only the `sub` key should be
        # used (here, in _generate_signup_values, and in _auth_oauth_signin)
        subject = next(
            filter(
                None,
                [
                    validation.pop(key, None)
                    for key in [
                        "sub",  # standard
                        "id",  # google v1 userinfo, facebook opengraph
                        "user_id",  # google tokeninfo, odoo (tokeninfo)
                    ]
                ],
            ),
            None,
        )
        if not subject:
            _logger.error("Access Denied: missing subject identity")
            raise AccessDenied()
        validation["user_id"] = subject

        return validation

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)
        if oauth_provider.flow == "id_token":
            access_token, id_token = self._auth_oauth_get_tokens_implicit_flow(
                oauth_provider, params
            )
        elif oauth_provider.flow == "id_token_code":
            access_token, id_token = self._auth_oauth_get_tokens_auth_code_flow(
                oauth_provider, params
            )
        else:
            return super().auth_oauth(provider, params)
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            raise AccessDenied()

        validation = self._auth_oauth_validate(provider, id_token, access_token)

        # retrieve and sign in user
        params["access_token"] = access_token
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        login = super()._auth_oauth_signin(provider, validation, params)
        user = self.search([("login", "=", login)])
        if user:
            group_updates = []
            for group_line in (
                self.env["auth.oauth.provider"].browse(provider).group_line_ids
            ):
                if group_line._eval_expression(user, validation):
                    if group_line.group_id not in user.groups_id:
                        group_updates.append(Command.link(group_line.group_id.id))
                else:
                    if group_line.group_id in user.groups_id:
                        group_updates.append(Command.unlink(group_line.group_id.id))
            if group_updates:
                user.write({"groups_id": group_updates})
        return login
