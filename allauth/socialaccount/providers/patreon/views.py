"""
Views for PatreonProvider
https://www.patreon.com/platform/documentation/oauth
"""

import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import API_URL, USE_API_V2, PatreonProvider


class PatreonOAuth2Adapter(OAuth2Adapter):
    provider_id = PatreonProvider.id
    access_token_url = "https://www.patreon.com/api/oauth2/token"
    authorize_url = "https://www.patreon.com/oauth2/authorize"
    profile_url = "{0}/{1}".format(
        API_URL,
        "identity?include=memberships,memberships.currently_entitled_tiers"
        "&fields%5Buser%5D=email,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity"
        "&fields%5Bmember%5D=last_charge_date,last_charge_status,next_charge_date,patron_status"
        if USE_API_V2
        else "current_user",
    )

    def complete_login(self, request, app, token, **kwargs):
        resp = requests.get(
            self.profile_url,
            headers={"Authorization": "Bearer " + token.token},
        )
        extra_data = resp.json().get('data')

        all_tiers = []
        try:
            for i in resp.json().get('included')[0]['relationships']['currently_entitled_tiers']['data']:
                all_tiers.append(i['id'])
            if '7161052' in all_tiers:
                extra_data['current_pledge'] = "Dungeon Merchant"
            elif '3313110' in all_tiers:
                extra_data['current_pledge'] = "Dungeon Architect"
            elif '3313098' in all_tiers:
                extra_data['current_pledge'] = "Dungeon Designer"
            elif '3313135' in all_tiers:
                extra_data['current_pledge'] = "Dungeon Planner"
            else:
                extra_data['current_pledge'] = None
        except Exception as e:
            extra_data['current_pledge'] = None
            extra_data['current_pledge_error'] = str(repr(e))

        try:
            extra_data['last_charge_date'] = resp.json().get('included')[0]['attributes']['last_charge_date']
        except Exception as e:
            extra_data['last_charge_date'] = None
            extra_data['last_charge_date_error'] = str(repr(e))

        try:
            extra_data['last_charge_status'] = resp.json().get('included')[0]['attributes']['last_charge_status']
        except Exception as e:
            extra_data['last_charge_status'] = None
            extra_data['last_charge_status_error'] = str(repr(e))

        try:
            extra_data['next_charge_date'] = resp.json().get('included')[0]['attributes']['next_charge_date']
        except Exception as e:
            extra_data['next_charge_date'] = None
            extra_data['next_charge_date_error'] = str(repr(e))

        try:
            extra_data['patron_status'] = resp.json().get('included')[0]['attributes']['patron_status']
        except Exception as e:
            extra_data['patron_status'] = None
            extra_data['patron_status_error'] = str(repr(e))

        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth2_login = OAuth2LoginView.adapter_view(PatreonOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(PatreonOAuth2Adapter)
