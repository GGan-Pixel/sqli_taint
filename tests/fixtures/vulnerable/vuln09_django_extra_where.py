def filter_extra(User, user_input):
    User.objects.extra(where=["id = " + user_input])  # EXPECT: SQLI
