<?php

namespace AET\EncryptionData\DataGateway;

use AET\EncryptionData\Exceptions\ErrorException;

class DataGateway {

    public $config;

    private $_merchantkey	= null,
            $_systemkey 	= null;

    public function __construct($config = []) {
        $this->config = $config;
        $this->loadKeys();
    }

    public function __call($name, $arguments) {
        return $this->exec($name, $arguments[0]);
    }

    public function prepare($array_data) {

        $clean_data = json_encode($array_data);

        $sign = $this->sign($clean_data);
        $tmp  = $this->encrypt($clean_data);

        /* Base64 encode everything */
        $sign = base64_encode($sign);
        $key  = base64_encode($tmp['key']);
        $data = base64_encode($tmp['data']);

        /* Form request */
        $request = new \stdClass();
        $request->KEY = $key;
        $request->REQUEST_DATA = $data;
        $request->SIGNATURE = $sign;

        return $request;

    }

    public function parse($response) {

        $sign = base64_decode($response->SIGNATURE);
        $key  = base64_decode($response->KEY);
        $data = base64_decode($response->REQUEST_DATA);

        $data = $this->decrypt($data, $key);

        if (!$this->checkSignature($data, $sign)) {
            throw new ErrorException('Decryption failed, invalid signature!');
        }

        return json_decode($data);

    }

    private function sign($clean_data) {
        $merchantkeyid = openssl_get_privatekey($this->_merchantkey);
        if (!openssl_sign($clean_data, $sign, $merchantkeyid)) {
            throw new ErrorException('Signing failed: ' . openssl_error_string());
        }
        openssl_free_key($merchantkeyid);

        return $sign;
    }

    private function checkSignature($data, $sign) {
        $systemkeyid = openssl_get_publickey($this->_systemkey);
        $res = (openssl_verify($data, $sign, $systemkeyid) == 1);
        openssl_free_key($systemkeyid);

        return $res;
    }

    private function encrypt($cleardata) {
        $systemkeyid = openssl_get_publickey($this->_systemkey);
        if (openssl_seal($cleardata, $data, $ekeys, array($systemkeyid))) {
            $key = $ekeys[0];
        } else {
            throw new ErrorException('Encryption failed: ' . openssl_error_string());
        }
        openssl_free_key($systemkeyid);

        return array(
            'data' => $data,
            'key' => $key,
        );
    }

    private function decrypt($data, $key) {
        $merchantkeyid = openssl_get_privatekey($this->_merchantkey);
        if (!openssl_open($data, $cleardata, $key, $merchantkeyid)) {
            throw new ErrorException('Decryption failed: ' . openssl_error_string());
        };
        openssl_free_key($merchantkeyid);

        return $cleardata;
    }

    public function loadKeys() {

        $m_keyfile = fopen($this->config['private_key'], 'r');
        $this->_merchantkey = fread($m_keyfile, filesize($this->config['private_key']));
        fclose($m_keyfile);

        $s_keyfile = fopen($this->config['public_key'], 'r');
        $this->_systemkey = fread($s_keyfile, filesize($this->config['public_key']));
        fclose($s_keyfile);

        unset($m_keyfile);
        unset($s_keyfile);
    }
}