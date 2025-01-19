from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth import authenticate, login, get_user_model
from django.core.exceptions import ObjectDoesNotExist
from .serializers import UserSerializer, UserDetailSerializer

User = get_user_model()

class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                'error': 'Please provide both username and password'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists
        if not User.objects.filter(username=username).exists():
            return Response({
                'error': 'User is not registered. Please register first.'
            }, status=status.HTTP_404_NOT_FOUND)

        # Try to authenticate
        user = authenticate(username=username, password=password)
        if not user:
            return Response({
                'error': 'Invalid password'
            }, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': UserDetailSerializer(user).data
        })

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        Token.objects.create(user=user)

class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user

class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if username is None or password is None:
            return Response({
                'error': 'Please provide both username and password'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user exists
            user_exists = User.objects.filter(username=username).exists()
            if not user_exists:
                return Response({
                    'error': 'User is not registered. Please register first.'
                }, status=status.HTTP_404_NOT_FOUND)

            # Try to authenticate
            user = authenticate(username=username, password=password)
            if not user:
                return Response({
                    'error': 'Invalid password'
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get or create token
            token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                'token': token.key,
                'user': UserDetailSerializer(user).data
            })

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserRegistrationView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')

        if not all([username, password, email]):
            return Response({
                'error': 'Please provide username, password and email'
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({
                'error': 'Username already exists'
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'Email already exists'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username,
            password=password,
            email=email
        )

        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username
        }, status=status.HTTP_201_CREATED)
