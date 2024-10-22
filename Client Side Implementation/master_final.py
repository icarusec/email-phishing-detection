import re
import dns.resolver
import logging
import os

# Custom Modules
import threading_realtime_two as real_time
import blacklist_pulldown
import mongodb_final as mongodb


# Create a logger instance
logger = logging.getLogger(__name__)

# Set the logging level (optional)
logger.setLevel(logging.INFO)

def get_mx_record(domain):
    try:
        # Get the MX record for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
        return mx_record.exchange.to_text().strip()  # Remove any extra spaces and periods
    except Exception as e:
        print(f"An error occurred while fetching MX record: {e}")
        return None

def server_fetch(email_address, password):
    # Dictionary of common email providers and their IMAP servers
    IMAP_SERVERS = {
        'gmail.com': 'imap.gmail.com',
        'yahoo.com': 'imap.mail.yahoo.com',
        'outlook.com': 'imap-mail.outlook.com',
        'hotmail.com': 'imap-mail.outlook.com',
        'live.com': 'imap-mail.outlook.com',
        'aol.com': 'imap.aol.com',
        'icloud.com': 'imap.mail.me.com',
        'google.com': 'imap.gmail.com',
        'aspmx.l.google.com': 'imap.gmail.com',
        'mta5.am0.yahoodns.net': 'imap.mail.yahoo.com',
        'mta6.am0.yahoodns.net': 'imap.mail.yahoo.com',
        'mta7.am0.yahoodns.net': 'imap.mail.yahoo.com', # Specific handling for MX server
    }
    # Split the email to get the domain
    domain = email_address.split('@')[1]
    if not domain:
        print("Invalid email address.")
        return None

    # Check if the domain is in the dictionary
    email_server = IMAP_SERVERS.get(domain)
    if not email_server:
        # If the domain is not in the dictionary, get the MX record
        mx_server = get_mx_record(domain)
        if not mx_server:
            print(f"Failed to retrieve MX record for domain: {domain}")
            return None

        # Remove trailing period if present
        mx_server = mx_server.rstrip('.')

        email_server = IMAP_SERVERS.get(mx_server)
        if email_server:
            return email_address, password, email_server
        else:
            # Extract the base domain using regex
            match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]+)$', mx_server)
            if match:
                base_domain = match.group(0)
                email_server = IMAP_SERVERS.get(base_domain, f'imap.{base_domain}')
            else:
                print(f"Failed to parse base domain from MX server: {mx_server}")
                return None

    return email_address, password, email_server



def mongodb_menu():
    print("\nUser Register and Login:")
    print("1. Register")
    print("2. Login")
    print("3. Delete user")
    print("4. Back to Main menu")
    

def display_menu():
    print("\nEmail Phishing Toolkit:")
    print("1. User Register and Login")
    print("2. Enable Real Time Monitoring")
    print("3. Exit")


def display_real_time_menu():
    print("\nReal Time Monitoring:")
    print("1. Update DNS blacklist")
    print("2. Execute Real Time Monitoring")
    print("3. Execute Real Time Monitoring Service")
    print("4. Set RMN Service")
    print("5. Remove RMN Service")
    print("6. Server Execution")
    print("7. Back to Main Menu")

def main():
    user, password, mail_server = None, None, None

    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            while True:
                mongodb_menu()
                credential_choice = input("Enter your choice: ")
                if credential_choice == '1':
                    mongodb.store_credentials()
                    
                elif credential_choice == '2':
                    result = mongodb.verify_password()
                    if result:
                        logger.info(f"User Email: {result['email']}")
                        logger.info(f"User App Pass: {result['app_pass']}")
                        logger.info(f"Alert Server Email: {result['alert_server_email']}")
                        logger.info(f"Alert Server App Pass: {result['alert_server_app_pass']}")
                        email = result['email']
                        password = result['app_pass']
                        server_email = result['alert_server_email']
                        server_pass = result['alert_server_app_pass']
                        user, password, mail_server = server_fetch(email, password)
                        print(f"Email Server : {mail_server}")
                elif credential_choice == '3': 
                    mongodb.delete_user()              
                elif credential_choice == '4':
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == '2':
            while True:
                display_real_time_menu()
                real_time_choice = input("Enter your choice: ")

                if real_time_choice == '1':
                    print("Updating DNS Blacklist...")
                    blacklist_pulldown.domain_db_update()
                    blacklist_pulldown.ip_db_update()

                elif real_time_choice == '2':
                    if user and password and mail_server:
                        print("Executing Real Time Monitoring...")
                        real_time.email_fetchncheck(user, password, mail_server , server_email, server_pass)
                    else:
                        print("Please configure email first.")

                elif real_time_choice == '3':
                        print("Executing Real Time Monitoring Service")
                        real_time.service()
                
                elif real_time_choice == '4':
                    os.system("chmod +x service_set.sh")
                    os.system("./service_set.sh")

                elif real_time_choice == '5':
                    os.system("chmod +x service_remove.sh")
                    os.system("./service_remove.sh")
                
                elif real_time_choice == '6':
                    print("Executing Email Monitoring Server")
                    
                elif real_time_choice == '7':
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
