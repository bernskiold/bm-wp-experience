<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitc6947907303abaaf7a0a6b488c10bb8a
{
    public static $files = array (
        '49a1299791c25c6fd83542c6fedacddd' => __DIR__ . '/..' . '/yahnis-elsts/plugin-update-checker/load-v4p11.php',
    );

    public static $prefixLengthsPsr4 = array (
        'C' => 
        array (
            'Composer\\Installers\\' => 20,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Composer\\Installers\\' => 
        array (
            0 => __DIR__ . '/..' . '/composer/installers/src/Composer/Installers',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitc6947907303abaaf7a0a6b488c10bb8a::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitc6947907303abaaf7a0a6b488c10bb8a::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitc6947907303abaaf7a0a6b488c10bb8a::$classMap;

        }, null, ClassLoader::class);
    }
}
