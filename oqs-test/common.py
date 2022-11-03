import os
import subprocess
import pathlib
import psutil
import time

key_exchanges = [
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','kyber512','kyber768','kyber1024','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hps40961229','ntru_hrss701','ntru_hrss1373','lightsaber','saber','firesaber','bikel1','bikel3','kyber90s512','kyber90s768','kyber90s1024','hqc128','hqc192','hqc256','ntrulpr653','ntrulpr761','ntrulpr857','ntrulpr1277','sntrup653','sntrup761','sntrup857','sntrup1277',
    # post-quantum + classical key exchanges
    'p256_frodo640aes','p256_frodo640shake','p384_frodo976aes','p384_frodo976shake','p521_frodo1344aes','p521_frodo1344shake','p256_kyber512','p384_kyber768','p521_kyber1024','p256_ntru_hps2048509','p384_ntru_hps2048677','p521_ntru_hps4096821','p521_ntru_hps40961229','p384_ntru_hrss701','p521_ntru_hrss1373','p256_lightsaber','p384_saber','p521_firesaber','p256_bikel1','p384_bikel3','p256_kyber90s512','p384_kyber90s768','p521_kyber90s1024','p256_hqc128','p384_hqc192','p521_hqc256','p256_ntrulpr653','p256_ntrulpr761','p384_ntrulpr857','p521_ntrulpr1277','p256_sntrup653','p256_sntrup761','p384_sntrup857','p521_sntrup1277',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_END
]
signatures = [
    'ecdsap256', 'rsa3072',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_START
    # post-quantum signatures
    'dilithium2','sphincsharaka128frobust','sphincsharaka128fsimple','sphincsharaka128srobust','sphincsharaka128ssimple','sphincsharaka192frobust','sphincsharaka192fsimple','sphincsharaka192srobust','sphincsharaka192ssimple','sphincsharaka256frobust','sphincsharaka256fsimple','sphincsharaka256srobust','sphincsharaka256ssimple','sphincssha256128frobust','sphincssha256128fsimple','sphincssha256128srobust','sphincssha256128ssimple','sphincssha256192frobust','sphincssha256192fsimple','sphincssha256192srobust','sphincssha256192ssimple','sphincssha256256frobust','sphincssha256256fsimple','sphincssha256256srobust','sphincssha256256ssimple','sphincsshake256128frobust','sphincsshake256128fsimple','sphincsshake256128srobust','sphincsshake256128ssimple','sphincsshake256192frobust','sphincsshake256192fsimple','sphincsshake256192srobust','sphincsshake256192ssimple','sphincsshake256256frobust','sphincsshake256256fsimple','sphincsshake256256srobust','sphincsshake256256ssimple',
    # post-quantum + classical signatures
    'p256_dilithium2','rsa3072_dilithium2','p256_sphincsharaka128frobust','rsa3072_sphincsharaka128frobust','p256_sphincsharaka128fsimple','rsa3072_sphincsharaka128fsimple','p256_sphincsharaka128srobust','rsa3072_sphincsharaka128srobust','p256_sphincsharaka128ssimple','rsa3072_sphincsharaka128ssimple','p384_sphincsharaka192frobust','p384_sphincsharaka192fsimple','p384_sphincsharaka192srobust','p384_sphincsharaka192ssimple','p521_sphincsharaka256frobust','p521_sphincsharaka256fsimple','p521_sphincsharaka256srobust','p521_sphincsharaka256ssimple','p256_sphincssha256128frobust','rsa3072_sphincssha256128frobust','p256_sphincssha256128fsimple','rsa3072_sphincssha256128fsimple','p256_sphincssha256128srobust','rsa3072_sphincssha256128srobust','p256_sphincssha256128ssimple','rsa3072_sphincssha256128ssimple','p384_sphincssha256192frobust','p384_sphincssha256192fsimple','p384_sphincssha256192srobust','p384_sphincssha256192ssimple','p521_sphincssha256256frobust','p521_sphincssha256256fsimple','p521_sphincssha256256srobust','p521_sphincssha256256ssimple','p256_sphincsshake256128frobust','rsa3072_sphincsshake256128frobust','p256_sphincsshake256128fsimple','rsa3072_sphincsshake256128fsimple','p256_sphincsshake256128srobust','rsa3072_sphincsshake256128srobust','p256_sphincsshake256128ssimple','rsa3072_sphincsshake256128ssimple','p384_sphincsshake256192frobust','p384_sphincsshake256192fsimple','p384_sphincsshake256192srobust','p384_sphincsshake256192ssimple','p521_sphincsshake256256frobust','p521_sphincsshake256256fsimple','p521_sphincsshake256256srobust','p521_sphincsshake256256ssimple',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_END
]

SERVER_START_ATTEMPTS = 10

def run_subprocess(command, working_dir='.', expected_returncode=0, input=None, env=None):
    """
    Helper function to run a shell command and report success/failure
    depending on the exit status of the shell command.
    """

    # Note we need to capture stdout/stderr from the subprocess,
    # then print it, which pytest will then capture and
    # buffer appropriately
    print(working_dir + " > " + " ".join(command))
    result = subprocess.run(
        command,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        env=env
    )
    if result.returncode != expected_returncode:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode('utf-8')

def start_server(ossl, test_artifacts_dir, sig_alg, worker_id):
    command = [ossl, 's_server',
                      '-cert', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_alg)),
                      '-key', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_alg)),
                      '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_alg)),
                      '-tls1_3',
                      '-quiet',
                      # On UNIX-like systems, binding to TCP port 0
                      # is a request to dynamically generate an unused
                      # port number.
                      # TODO: Check if Windows behaves similarly
                      '-accept', '0']

    print(" > " + " ".join(command))
    server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    server_info = psutil.Process(server.pid)

    # Try SERVER_START_ATTEMPTS times to see
    # what port the server is bound to.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        if server_info.connections():
            break
        else:
            server_start_attempt += 1
            time.sleep(2)
    server_port = str(server_info.connections()[0].laddr.port)

    # Check SERVER_START_ATTEMPTS times to see
    # if the server is responsive.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        result = subprocess.run([ossl, 's_client', '-connect', 'localhost:{}'.format(server_port)],
                                input='Q'.encode(),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode == 0:
            break
        else:
            server_start_attempt += 1
            time.sleep(2)

    if server_start_attempt > SERVER_START_ATTEMPTS:
        raise Exception('Cannot start OpenSSL server')

    return server, server_port

def gen_keys(ossl, ossl_config, sig_alg, test_artifacts_dir, filename_prefix):
    pathlib.Path(test_artifacts_dir).mkdir(parents=True, exist_ok=True)
    if sig_alg == 'ecdsap256':
        run_subprocess([ossl, 'ecparam',
                              '-name', 'prime256v1',
                              '-out', os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))])
        run_subprocess([ossl, 'req', '-x509', '-new',
                                     '-newkey', 'ec:{}'.format(os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))),
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_ecdsap256_CA.key'.format(filename_prefix)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_ecdsap256_CA.crt'.format(filename_prefix)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_CA',
                                         '-days', '365',
                                     '-config', ossl_config])
        run_subprocess([ossl, 'req', '-new',
                                     '-newkey', 'ec:{}'.format(os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))),
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_ecdsap256_srv.key'.format(filename_prefix)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_ecdsap256_srv.csr'.format(filename_prefix)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_server',
                                     '-config', ossl_config])
    else:
        if sig_alg == 'rsa3072':
            ossl_sig_alg_arg = 'rsa:3072'
        else:
            ossl_sig_alg_arg = sig_alg
        run_subprocess([ossl, 'req', '-x509', '-new',
                                     '-newkey', ossl_sig_alg_arg,
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_CA',
                                         '-days', '365',
                                     '-config', ossl_config])
        run_subprocess([ossl, 'req', '-new',
                              '-newkey', ossl_sig_alg_arg,
                              '-keyout', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(filename_prefix, sig_alg)),
                              '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                              '-nodes',
                                  '-subj', '/CN=oqstest_server',
                              '-config', ossl_config])

    run_subprocess([ossl, 'x509', '-req',
                                  '-in', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                                  '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(filename_prefix, sig_alg)),
                                  '-CA', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg)),
                                  '-CAkey', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                  '-CAcreateserial',
                                  '-days', '365'])

    # also create pubkeys from certs for dgst verify tests:
    env = os.environ
    env["OPENSSL_CONF"]=os.path.join("apps", "openssl.cnf")
    run_subprocess([ossl, 'req',
                                  '-in', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                                  '-pubkey', '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.pubk'.format(filename_prefix, sig_alg)) ],
                   env=env)
