# SECURE PASSWORD KEEPER V1.0
## MOTD Resource -- /motd
MOTD displays a small message.
## User Resource -- /user
#### User Model
    username String
    password String
    acc_type Int
### User Create Resource -- /user/create -- Methods = POST
Verifies entered data and determines if username already exists.
#### Post Data
    username Required
    password Required
    acc_type Optional (Defaults to 1, a regular user account)
### User Login Resource -- /user/login - Method:Get
Basic Authentication.
Returns a token, default timeout is 120 seconds.
## Password Keeper Resource -- /password
#### Password Model
    user_id ForignKey(user.id)
    service String
    enc_password String
    aes_iv String
### Set Password -- /password/set - Method:Post
Sets Password for a given Service.
Requires basic Authentication with user token.
#### Post Data
    service Required
    password Required
### Get Password -- /password/get/<service> - Method:Get
Gets Password of specific Service
Requires basic Authentication with user token.
### Get all Password -- /password/get/all - Method:Get
Gets all Passwords for user.
Requires basic Authentication with user token.

##TODOS:
####Priority: Must fix User Creation Resource. 
####In meantime do not create any more admins.

