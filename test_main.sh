echo "running ./make_users"
./make_users.sh
echo "completed ./make_users"
echo ""
echo "getting admin token"
admin=$(./get_token_admin.sh | grep -o '"token".*' | cut -f2- -d: | tr -d '"' | tr -d ' ')
echo "setting demonstration passwords for admin" $admin
./set_password.sh $admin gmail
./set_password.sh $admin discord
./set_password.sh $admin steam
echo "admin passwords set"
echo ""
echo "getting user token"
user=$(./get_token_user.sh | grep -o '"token".*' | cut -f2- -d: | tr -d '"' | tr -d ' ')
echo "setting demonstration passwords for user" $user
./set_password.sh $user stackextange
./set_password.sh $user outlook
./set_password.sh $user azure
echo "user passwords set"
echo ""
echo "getting passwords for admin"
./get_password.sh $admin gmail
./get_password.sh $admin discord
./get_password.sh $admin steam
echo ""
echo "getting passwords for user"
./get_password.sh $user stackextange
./get_password.sh $user outlook
./get_password.sh $user azure
echo ""
echo "attempting ./get_all_passwords.sh for user"
./get_all_passwords.sh $user
echo ""
echo "attempting ./get_all_passwords.sh for admin"
./get_all_passwords.sh $admin
