rule BrainCipher_Ransomware
{
    meta:
        description = "Identify Brain Cipher Ransomware samples found in the wild"
        author = "Spentera"
        author_email = "research@spentera.id"
        date = "2024-06-25"
        version = "1.0"

    strings:
        // 8B75 0C             mov esi,dword ptr ss:[ebp+C]
        // AD                  lodsd
        // 35 FF5F0310         xor eax,10035FFF
        // 50                  push eax
        // E8 6FFEFFFF         call 00B85C24
        // 85C0                test eax,eax
        // 0F84 23010000     je 00B85EE0
        // 8B7D 08             mov edi,dword ptr ss:[ebp+8]
        // 83C7 04             add edi,4
        $1 = { 8b 75 0c ad 35 ff 5f 03 10 50 e8 6f fe ff ff 85 c0 0f 84 23 01 00 00 8b 7d 08 83 c7 04 }
        // 83C4 F4             add esp,FFFFFFF4
        // 56                  push esi
        // C745 FC 00000000     mov dword ptr ss:[ebp-4],0
        // C745 F8 00000000     mov dword ptr ss:[ebp-8],0
        // E8 46EDFEFF         call 00B81640
        // 8BC8                mov ecx,eax
        // 8D45 F4             lea eax,dword ptr ss:[ebp-C]
        // 50                  push eax
        // 51                  push ecx
        // FF15 2C57BA00         call dword ptr ds:[BA572C]
        // 8945 F8             mov dword ptr ss:[ebp-8],eax
        // 837D F8 00          cmp dword ptr ss:[ebp-8],0
        // 74 2B               je 00B9293B
        // 837D F4 02          cmp dword ptr ss:[ebp-C],2
        // 72 25               jb 00B9293B
        // 8B75 F8             mov esi,dword ptr ss:[ebp-8]
        $2 = { 83 c4 f4 56 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 e8 46 ed fe ff 8b c8 8d 45 f4 50 51 ff 15 2c 57 42 00 89 45 f8 83 7d f8 00 74 2b 83 7d f4 02 72 25 8b 75 f8 }
        // 8BC1             mov eax,ecx
        // 33D2             xor edx,edx
        // F7F6             div esi
        // 8AC1             mov al,cl
        // 8A1417           mov dl,byte ptr ds:[edi+edx]
        // 025405 00        add dl,byte ptr ss:[ebp+eax]
        // 02D3             add dl,bl
        // 8A5C15 00        mov bl,byte ptr ss:[ebp+edx]
        // 8A541D 00        mov dl,byte ptr ss:[ebp+ebx]
        // 865405 00        xchg byte ptr ss:[ebp+eax],dl
        // 88541D 00        mov byte ptr ss:[ebp+ebx],dl
        // 41               inc ecx
        // 81F9 00030000     cmp ecx,300
        // 75 D6            jne 00B993AE
        // 5D               pop ebp
        // 33C9             xor ecx,ecx
        // 8B7D 0C          mov edi,dword ptr ss:[ebp+C]
        // BE 40000000      mov esi,40
        // 55               push ebp
        // 8B6D 10          mov ebp,dword ptr ss:[ebp+10]
        $3 = { 8b c1 33 d2 f7 f6 8a c1 8a 14 17 02 54 05 00 02 d3 8a 5c 15 00 8a 54 1d 00 86 54 05 00 88 54 1d 00 41 81 f9 00 03 00 00 75 d6 5d 33 c9 8b 7d 0c be 40 00 00 00 55 8b 6d 10 }

    condition:
        uint16(0) == 0x5a4d and filesize < 170KB and ($1 or $2 or $3)
}