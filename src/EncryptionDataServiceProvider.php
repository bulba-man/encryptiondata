<?php

namespace AET\EncryptionData;

use Illuminate\Support\ServiceProvider;

class EncryptiondataServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register any package services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind('encryptiondata', 'AET\EncryptionData\EncryptionData');

        $config = __DIR__ . '/../config/encryptiondata.php';
        $this->mergeConfigFrom($config, 'encryptiondata');

        $this->publishes([__DIR__ . '/../config/encryptiondata.php' => config_path('encryptiondata.php')], 'config');




    }
}