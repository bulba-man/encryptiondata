<?php
namespace AET\EncryptionData\Facades;

use Illuminate\Support\Facades\Facade;

class EncryptionData extends Facade {
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'encryptiondata';
    }
}
