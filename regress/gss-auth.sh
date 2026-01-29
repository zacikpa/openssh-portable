tid="GSSAPI Authentication"

# Skip the test if GSSAPI support is not configured
if ! grep -E '^#define GSSAPI' $BUILDDIR/config.h >/dev/null 2>&1; then
    skip "GSSAPI not enabled"
fi

# We test with MIT Kerberos KDC, skip if not installed
if ! which krb5kdc >/dev/null 2>&1; then
    skip "MIT Kerberos KDC not installed"
fi

# The test needs nss_wrapper to emulate hostnames and name resolution,
# we skip if the shared library is not installed
NSS_WRAPPER="libnss_wrapper.so"
if ! ldconfig -p | grep $NSS_WRAPPER >/dev/null 2>&1; then
    skip "$NSS_WRAPPER not installed"
fi

# Set up the username of the SSH client
CLIENT="$LOGNAME"
if [ "x$CLIENT" = "x" ]; then
	CLIENT=$(whoami)
fi

# Set up SSHD and KDC hostnames and resolve both to localhost
SSHD_HOSTNAME="sshd.example.org"
BAD_HOSTNAME="bad.example.org"
KDC_HOSTNAME="kdc.example.org"
KDC_PORT=2088
HOSTS=$OBJ/hosts
echo "127.0.0.1 $SSHD_HOSTNAME $KDC_HOSTNAME" > $HOSTS

# Set up a directory to store Kerberos data
# (configuration, ticket cache,...)
GSSDIR=$OBJ/gss
mkdir -p $GSSDIR
export KRB5CCNAME=$GSSDIR/cc
export KRB5_CONFIG=$GSSDIR/krb5.conf
export KRB5_KDC_PROFILE=$GSSDIR
export KRB5_KTNAME=$GSSDIR/ssh.keytab
export KRB5RCACHETYPE=none

# Configure Kerberos
cat<<EOF > $GSSDIR/kdc.conf
[realms]
    EXAMPLE.ORG = {
        database_name = $GSSDIR/principal
        key_stash_file = $GSSDIR/stash
        kdc_listen = $KDC_HOSTNAME:$KDC_PORT
        kdc_tcp_listen = $KDC_HOSTNAME:$KDC_PORT
    }
[logging]
    kdc = FILE:$GSSDIR/kdc.log
    debug = true
EOF

cat<<EOF > $GSSDIR/krb5.conf
[libdefaults]
    default_realm = EXAMPLE.ORG
[realms]
    EXAMPLE.ORG = {
        kdc = $KDC_HOSTNAME:$KDC_PORT
    }
EOF

setup_sshd() {
    mock_hostname=$1
    strict_acceptor=$2

    cp $OBJ/sshd_config $OBJ/sshd_config.orig

    cat<<EOF >> $OBJ/sshd_config
PubkeyAuthentication No
PasswordAuthentication No
GSSAPIAuthentication Yes
EOF

    if ! $strict_acceptor; then
        echo "GSSAPIStrictAcceptorCheck No" >> $OBJ/sshd_config
    fi

    TEST_SSH_SSHD_ENV_BACKUP=$TEST_SSH_SSHD_ENV
    TEST_SSH_SSHD_ENV="$TEST_SSH_SSHD_ENV \
                       LD_PRELOAD=$NSS_WRAPPER \
                       NSS_WRAPPER_HOSTS=$HOSTS \
                       NSS_WRAPPER_HOSTNAME=$mock_hostname \
                       KRB5_CONFIG=$GSSDIR/krb5.conf \
                       KRB5_KDC_PROFILE=$GSSDIR \
                       KRB5CCNAME=$GSSDIR/cc \
                       KRB5_KTNAME=$GSSDIR/ssh.keytab \
                       KRB5RCACHETYPE=none"
    start_sshd
}

teardown_sshd() {
    TEST_SSH_SSHD_ENV=$TEST_SSH_SSHD_ENV_BACKUP
    stop_sshd
    mv $OBJ/sshd_config.orig $OBJ/sshd_config
}

setup_kdc() {
    kdb5_util create -P foo -s
    krb5kdc -w 1 -P $GSSDIR/pid
    i=0;
    while [ ! -f $GSSDIR/pid -a $i -lt 10 ]; do
        i=$((i + 1))
        sleep 1
    done
    test -f $GSSDIR/pid || fatal "KDC failed to start"
}

teardown_kdc() {
    kill $(cat $GSSDIR/pid)
    kdestroy
    rm $KRB5_KTNAME
    kdb5_util destroy -f
}

setup_nss_emulation() {
    export LD_PRELOAD=$NSS_WRAPPER
    export NSS_WRAPPER_HOSTS=$HOSTS
}

teardown_nss_emulation() {
    unset LD_PRELOAD
    unset NSS_WRAPPER_HOSTS
}

setup_krb_principal_with_key() {
    name=$1
    add_to_keytab=$2
    kadmin.local add_principal -randkey $name
    if $add_to_keytab; then
        kadmin.local ktadd $name
    fi
}

setup_krb_principal_with_pw() {
    name=$1
    password=$2
    authenticate=$3
    kadmin.local add_principal -pw $password $name
    if $authenticate; then
        echo $password | kinit $name
    fi
}

test_gss_auth() {
    sshd_mock_hostname=$1 # the name that gethostname() will return within sshd
    sshd_principal=$2     # the hostname for which a Kerberos principal will be created
    auth_sshd=$3          # whether sshd will be authenticated via a keytab
    auth_client=$4        # whether the client will be authenticated via kinit
    strict_acceptor=$5    # whether to be strict about the identity of the sshd server
    expect=$6             # the expected return value of the sshd command

    setup_sshd $sshd_mock_hostname $strict_acceptor
    setup_nss_emulation
    setup_kdc

    setup_krb_principal_with_key "host/$sshd_principal" $auth_sshd
    setup_krb_principal_with_pw $CLIENT "foo" $auth_client

    ${SSH} -F $OBJ/ssh_config -o "GSSAPIAuthentication Yes" $CLIENT@$SSHD_HOSTNAME true
    status=$?

    teardown_kdc
    teardown_nss_emulation
    teardown_sshd

    [ $status -eq $expect ]
}

#              sshd_mock_hostname  sshd_principal  auth_sshd  auth_client  strict_acceptor  expect
test_gss_auth  $SSHD_HOSTNAME      $SSHD_HOSTNAME  true       true         true             0      \
               || fail "valid authentication attempt failed"
test_gss_auth  $SSHD_HOSTNAME      $SSHD_HOSTNAME  false      true         true             255    \
               || fail "authentication succeeded without a ticket-granting ticket"
test_gss_auth  $SSHD_HOSTNAME      $SSHD_HOSTNAME  true       false        true             255    \
               || fail "authentication succeeded without a keytab entry for the host"
test_gss_auth  $BAD_HOSTNAME       $SSHD_HOSTNAME  true       true         true             255    \
               || fail "authentication succeeded with a hostname/principal mismatch on server side"
test_gss_auth  $BAD_HOSTNAME       $SSHD_HOSTNAME  true       true         false            0      \
               || fail "valid authentication without strict acceptor check failed"
test_gss_auth  $BAD_HOSTNAME       $BAD_HOSTNAME   true       true         true             255    \
               || fail "authentication succeeded with a hostname/principal mismatch on client side"

unset KRB5CCNAME
unset KRB5_CONFIG
unset KRB5_KDC_PROFILE
unset KRB5_KTNAME
unset KRB5RCACHETYPE
rm -r $GSSDIR
