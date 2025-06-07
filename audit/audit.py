import boto3
import argparse

def check_public_s3_buckets(s3):
    print("\n🔍 Checking for public S3 buckets...")
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        name = bucket['Name']
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                print(f"[!] Public S3 Bucket Found: {name}")
                break

def check_insecure_iam(iam):
    print("\n🔍 Checking IAM roles and inline policies for wildcards...")
    roles = iam.list_roles()['Roles']
    for role in roles:
        role_name = role['RoleName']
        policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
        for policy_name in policies:
            policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            doc = policy['PolicyDocument']
            for stmt in doc.get('Statement', []):
                if stmt.get('Action') == '*' or stmt.get('Resource') == '*':
                    print(f"[!] IAM Role {role_name} has wildcard in policy: {policy_name}")

def check_ec2_public_ips(ec2):
    print("\n🔍 Checking EC2 instances with public IPs...")
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            public_ip = instance.get('PublicIpAddress')
            if public_ip:
                instance_id = instance['InstanceId']
                print(f"[!] EC2 Instance {instance_id} has public IP: {public_ip}")

def check_open_security_groups(ec2):
    print("\n🔍 Checking security groups with 0.0.0.0/0 ingress...")
    groups = ec2.describe_security_groups()['SecurityGroups']
    for sg in groups:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    print(f"[!] Security Group {sg['GroupId']} allows unrestricted access!")

def main():
    parser = argparse.ArgumentParser(description='AWS Security Audit CLI Tool')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS region')
    parser.add_argument('--profile', type=str, help='AWS profile name (optional)')
    args = parser.parse_args()

    session_args = {'region_name': args.region}
    if args.profile:
        session_args['profile_name'] = args.profile

    session = boto3.Session(**session_args)
    s3 = session.client('s3')
    iam = session.client('iam')
    ec2 = session.client('ec2')

    check_public_s3_buckets(s3)
    check_insecure_iam(iam)
    check_ec2_public_ips(ec2)
    check_open_security_groups(ec2)

if __name__ == "__main__":
    main()