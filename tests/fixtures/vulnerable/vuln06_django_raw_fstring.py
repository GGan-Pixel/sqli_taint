def find_user(User, status):
    User.objects.raw(f"SELECT * FROM auth_user WHERE status = '{status}'")  # EXPECT: SQLI
