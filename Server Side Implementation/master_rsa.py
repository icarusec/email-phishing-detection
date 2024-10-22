import mongodb_rsa as mongodb
import realtime_server as real_time

def server_menu():
    print("------Server-Menu------")
    print("1. Admin Panel")
    print("2. Execute Server Monitoring")
    print("3. Exit")

def admin_panel():
    print("------Admin-Panel------")
    print("1. Register User")
    print("2. Delete User")
    print("3. Update User")
    print("4. Exit")

def main():
    while True:
        server_menu()
        server_choice = int(input("Enter Choice : "))
        if server_choice == 1:
            while True:
                admin_panel()
                admin_choice = int(input("Enter Choice : "))
                if admin_choice == 1:
                    mongodb.store_credentials()
                if admin_choice == 2:
                    mongodb.remove_user()
                if admin_choice == 3:
                    mongodb.update_user()
                elif admin_choice == 4:
                    break
        elif server_choice == 2:
            real_time.server_service()

        elif server_choice == 3:
            print("Exiting....")
            break

main()



