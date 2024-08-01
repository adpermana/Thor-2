#!/bin/bash

echo " ░▀█▀░█▀▀▄░█▀▀░░▀░░█▀▄░█▀▀░█▀▀▄░▀█▀░░▀░░█░░░░░░▀░░█▀▄ \n"
echo " ░▒█░░█░▒█░▀▀▄░░█▀░█░█░█▀▀░█░▒█░░█░░░█▀░█░░▄▄░░█▀░█░█ \n"
echo " ░▄█▄░▀░░▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░▀░░▀░░▀░░▀▀▀░▀▀░▀▀░▀▀▀░▀▀░ \n"
echo "        Insidentil.id x Thor-Lite Scanner               "
echo " ${insidentil}                  by @insidentil${reset}\n"                                                                              

current_script_name="$(basename "$0")"

if [[ "$current_script_name" != "insidentil.sh" ]]; then
  echo "Salah, silahkan masukkan command dengan benar"
  exit 1
fi

echo "Melakukan Update keseluruhan"
chmod +x thor-lite-util
chmod +x thor-lite-linux
./thor-lite-util update
echo "Selesai Mengupdate"

echo "Melakukan Upgrade keseluruhan"
./thor-lite-util upgrade
echo "Selamat semua persiapan sudah siap"

echo "Melakukan Pemindai"
./thor-lite-linux
ls -la