<?php

namespace AET\EncryptionData;

use AET\EncryptionData\DataGateway\DataGateway;
use AET\EncryptionData\Exceptions\ErrorException;

class EncryptionData
{

    private static $required = array('KEY', 'REQUEST_DATA', 'SIGNATURE');
    private $DataGateway;

    public function __construct()
    {

    }

    public function encodeAndSend($data, $agent)
    {
        $this->DataGateway = new DataGateway( config('encryptiondata.keys.client') );

        $prepare = $this->prepare($data, $agent);
        $response = $this->send($prepare, $agent);
        return $response;
    }

    public function getAndDecode($data, $agent)
    {
        $this->DataGateway = new DataGateway( config('encryptiondata.keys.server') );
        $request = $this->decode($data, $agent);
        return $request;
    }

    public function send($prepare, $agent)
    {

        $fields = $prepare;
        $raw_response = $this->do_post_request($agent['url'], http_build_query($fields));

        $response = json_decode($raw_response, true);

        if (config('encryptiondata.encode')) {
            $response = (array)$this->decodeData($response);
        }
        if (config('encryptiondata.encrypt')) {
            $response = $this->decrypt_true((array)$response, $agent);
        }

        $response = (array)$response;

        if (isset($response['hash'])) {
            unset($response['hash']);
        }

        return (array)$response;
    }


    public function do_post_request($url, $data, $optional_headers = null)
    {
        error_reporting(E_ALL);
        ini_set('track_errors', 1);

        global $php_errormsg;

        $params = ['http' => [
            'method' => 'POST',
            'content' => $data
        ]];

        if ($optional_headers !== null) {
            $params['http']['header'] = $optional_headers;
        } else {
            $params['http']['header'] = "Content-Type: application/x-www-form-urlencoded\r\n".
                "Content-Length: ".strlen($data)."\r\n".
                "User-Agent:MyAgent/1.0\r\n";
        }

        $ctx = stream_context_create($params);
        $fp = @fopen($url, 'rb', false, $ctx);


        if (!$fp) {
            throw new ErrorException("Problem with $url, $php_errormsg");
        }

        $response = @stream_get_contents($fp);
       // echo $response; die;
        if ($response === false) {
            throw new ErrorException("Problem reading data from $url, $php_errormsg");
        }

        return $response;
    }


    public function decode($post_raw, $agent)
    {

        parse_str($post_raw, $post);
        if (config('encryptiondata.encode') == true) {
            $post = (array)$this->decodeData($post);
        }

        if (config('encryptiondata.encrypt') == true) {
            $post = $this->decrypt_true($post, $agent);
        }

        $post = (array)$post;
        unset($post['hash']);
        return $post;
    }

    /**
     * Returns array which should be POST'ed to FORMs URL
     * May throw Exception
     */
    public function encodeData($data) {

        $request = $this->DataGateway->prepare($data);
        return (array) $request;
    }

    /**
     * Takes array as an argument
     * May throw Exception
     */
    public function decodeData($response) {
        $response = (array) $response;

        if (count(array_diff(self::$required, array_keys($response))) > 0) {
            throw new ErrorException('Some of required POST params are not included!');
        }

        // Convert array to object
        $responseObj = new \stdClass();
        foreach ($response as $key => $value) {
            $responseObj->$key = $value;
        }

        return $this->DataGateway->parse($responseObj);

    }






    public function prepare(array $data, $agent)
    {
        $data = (array)$data;
        $fields = $data;

        if (config('encryptiondata.encrypt') == true) {
            $fields = $this->encrypt($fields, $agent);
        }

        if (config('encryptiondata.encode') == true) {
            $fields = $this->encodeData($fields);
        }

        return $fields;
    }


    public function encrypt($data, $agent)
    {
        $auth_key = $agent['secret_key'];
        $secret_key = $agent['auth_key'];
        $query = "auth_key={$auth_key}&body_md5=" . md5(json_encode($data));
        $data['hash'] = hash_hmac('sha256', $query, $secret_key, false);
        return $data;
    }


    public function decrypt_true($data, $agent)
    {

        $hash = @$data['hash'];
        unset($data['hash']);
        $data_clear = [];
        foreach ($data as $key => $row) {
            if ($key != 'hash') $data_clear[$key] = $row;
        }
        $hash_check = $this->encrypt($data_clear, $agent)['hash'];
        $data_clear['hash'] = $hash_check;
        if ($hash == $hash_check)
            return $data_clear;
        else
            false;

    }












}
