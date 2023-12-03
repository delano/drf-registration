
import logging

from django.contrib.auth import password_validation
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views import View
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_registration.settings import drfr_settings
from drf_registration.tokens import activation_token
from drf_registration.utils.common import import_string, import_string_list
from drf_registration.utils.domain import get_current_domain
from drf_registration.utils.email import send_verify_email, send_email_welcome
from drf_registration.utils.users import (
    get_user_profile_data,
    get_user_serializer,
    has_user_activate_token,
    has_user_verify_code,
    set_user_verified,
    get_user_from_uid,
)

logger = logging.getLogger(__name__)


class RegisterSerializer(get_user_serializer()):
    """
    User register serializer
    """

    def validate_password(self, value):
        """
        Validate user password
        """

        password_validation.validate_password(value, self.instance)
        return value

    def create(self, validated_data):
        """
        Override create method to create user password
        """

        user = super().create(validated_data)
        user.set_password(validated_data['password'])

        # Disable verified if enable verify user, else set it enabled
        user_verified = not (has_user_activate_token() or has_user_verify_code())
        set_user_verified(user, user_verified)
        user.save()
        return user


class RegisterView(CreateAPIView):
    """
    Register a new user to the system
    """

    permission_classes = import_string_list(drfr_settings.REGISTER_PERMISSION_CLASSES)
    serializer_class = import_string(drfr_settings.REGISTER_SERIALIZER)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        # This approach instantiates the serializer again. It's not ideal
        # b/c it inefficient and also leads to an exception in cases where
        # the user serializer needs the request object (e.g. to get the
        # current domain, current user id etc for generating REST links).
        #
        # data = get_user_profile_data(user)

        # Using the serializer we just instantiated, we can get the same
        # data and avoid a HyperlinkedIdentityField exception.
        #
        # e.g.
        # {
        #     "id": "dd2e10a2-7ad2-4e29-9444-018907034352",
        #     "url": "http://127.0.0.1:8000/api/users/dd2e10a2-7ad2-4e29-9444-018907034352/",
        #     "username": null,
        #     "email": "a1@example.com",
        #     "is_staff": false
        # }
        #
        data = serializer.data

        domain = get_current_domain(request)

        # Send email activation link
        try:
            if has_user_activate_token() or has_user_verify_code():
                send_verify_email(user, domain)
            else:
                send_email_welcome(user)

        except ConnectionRefusedError as e:
            # Simply log the error and continue
            largs = (user.email, e)
            emsg = 'Failed to send welcome email to: %s (%s)' % largs
            logger.critical(emsg)

        except Exception as e:
            # For all other errors, log the error and continue as
            # well. This is to prevent the registration process from
            # failing due to an email error.
            largs = (user.email, e)
            emsg = 'Failed to send welcome email to: %s (%s)' % largs
            logger.error(emsg)


        return Response(data, status=status.HTTP_201_CREATED)


class VerifyView(APIView):
    """
    Activate account by use code sent to email
    """


class ActivateView(View):
    """
    Activate account by use token sent to email
    """

    def get(self, request, uidb64, token):
        """
        Override to get the activation uid and token

        Args:
            request (object): Request object
            uidb64 (string): The uid
            token (string): The user token

        """

        user = get_user_from_uid(uidb64)

        if user and activation_token.check_token(user, token):
            set_user_verified(user)

            send_email_welcome(user)

            if drfr_settings.USER_ACTIVATE_SUCCESS_TEMPLATE:
                return render(request, drfr_settings.USER_ACTIVATE_SUCCESS_TEMPLATE)  # pragma: no cover
            return HttpResponse(_('Your account has been activate successfully.'))

        if drfr_settings.USER_ACTIVATE_FAILED_TEMPLATE:
            return render(request, drfr_settings.USER_ACTIVATE_FAILED_TEMPLATE)  # pragma: no cover
        return HttpResponse(
            _('Either the provided activation token is invalid or this account has already been activated.')
        )
