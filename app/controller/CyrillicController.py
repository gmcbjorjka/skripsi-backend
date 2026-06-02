from flask import request, jsonify
import unicodedata

# Peta homoglyph: Cyrillic → Latin asli
CYRILLIC_TO_LATIN_MAP = {
    # Huruf kecil
    'а': 'a',  # U+0430 CYRILLIC SMALL LETTER A
    'е': 'e',  # U+0435 CYRILLIC SMALL LETTER IE
    'о': 'o',  # U+043E CYRILLIC SMALL LETTER O
    'р': 'p',  # U+0440 CYRILLIC SMALL LETTER ER
    'с': 'c',  # U+0441 CYRILLIC SMALL LETTER ES
    'х': 'x',  # U+0445 CYRILLIC SMALL LETTER HA
    'і': 'i',  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    'ѕ': 's',  # U+0455 CYRILLIC SMALL LETTER DZE
    'ј': 'j',  # U+0458 CYRILLIC SMALL LETTER JE
    'ԁ': 'd',  # U+0501 CYRILLIC SMALL LETTER KOMI DE
    'ԛ': 'q',  # U+051B CYRILLIC SMALL LETTER QA
    'ԝ': 'w',  # U+051D CYRILLIC SMALL LETTER WE
    'у': 'y',  # U+0443 CYRILLIC SMALL LETTER U (looks like y)
    'ь': 'b',  # U+044C CYRILLIC SMALL LETTER SOFT SIGN (looks like b)
    'п': 'n',  # U+043F CYRILLIC SMALL LETTER PE (looks like n)
    'г': 'r',  # U+0433 CYRILLIC SMALL LETTER GHE (looks like r)
    # Huruf besar
    'А': 'A',  # U+0410 CYRILLIC CAPITAL LETTER A
    'В': 'B',  # U+0412 CYRILLIC CAPITAL LETTER VE
    'Е': 'E',  # U+0415 CYRILLIC CAPITAL LETTER IE
    'К': 'K',  # U+041A CYRILLIC CAPITAL LETTER KA
    'М': 'M',  # U+041C CYRILLIC CAPITAL LETTER EM
    'Н': 'H',  # U+041D CYRILLIC CAPITAL LETTER EN
    'О': 'O',  # U+041E CYRILLIC CAPITAL LETTER O
    'Р': 'P',  # U+0420 CYRILLIC CAPITAL LETTER ER
    'С': 'C',  # U+0421 CYRILLIC CAPITAL LETTER ES
    'Т': 'T',  # U+0422 CYRILLIC CAPITAL LETTER TE
    'Х': 'X',  # U+0425 CYRILLIC CAPITAL LETTER HA
    'І': 'I',  # U+0406 CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    'Ѕ': 'S',  # U+0405 CYRILLIC CAPITAL LETTER DZE
    'Ј': 'J',  # U+0408 CYRILLIC CAPITAL LETTER JE
    'Ԁ': 'D',  # U+0500 CYRILLIC CAPITAL LETTER KOMI DE
}


def _is_cyrillic(char):
    """Cek apakah karakter masuk dalam range Unicode Cyrillic"""
    cp = ord(char)
    return (0x0400 <= cp <= 0x04FF) or (0x0500 <= cp <= 0x052F)


def _char_info(char):
    """Buat dict info detail untuk satu karakter"""
    is_cyr = _is_cyrillic(char)
    latin_equiv = CYRILLIC_TO_LATIN_MAP.get(char, None) if is_cyr else None
    return {
        'character': char,
        'unicode_code': ord(char),
        'unicode_hex': f'U+{ord(char):04X}',
        'name': unicodedata.name(char, 'Unknown'),
        'category': unicodedata.category(char),
        'is_cyrillic': is_cyr,
        'latin_equivalent': latin_equiv,
    }


def analyze_cyrillic():
    """
    Analisis dan tampilkan karakter asli dari huruf Cyrillic.
    Input : JSON { "text": "..." }
    Output: Detail setiap karakter + teks hasil konversi homoglyph ke Latin
    """
    try:
        data = request.get_json()

        if not data or 'text' not in data:
            return jsonify({
                'success': False,
                'message': 'Text field tidak boleh kosong'
            }), 400

        input_text = data.get('text', '').strip()

        if not input_text:
            return jsonify({
                'success': False,
                'message': 'Text harus diisi'
            }), 400

        # Analisis setiap karakter
        all_characters = [_char_info(c) for c in input_text]
        cyrillic_only = [ci for ci in all_characters if ci['is_cyrillic']]

        # Konversi homoglyph Cyrillic → Latin (untuk menampilkan karakter asli)
        converted_text = ''.join(
            CYRILLIC_TO_LATIN_MAP.get(c, c) for c in input_text
        )

        # Deteksi dan Decode Punycode (IDN)
        punycode_info = {
            'is_punycode': False,
            'decoded_text': None,
            'encoded_punycode': None  # Tambahkan field untuk versi encoded
        }
        
        # Selalu coba buat versi Punycode dari input
        try:
            # Jika input mengandung karakter non-ascii, buat versi xn--
            punycode_info['encoded_punycode'] = input_text.encode('idna').decode('ascii')
        except:
            punycode_info['encoded_punycode'] = input_text

        if 'xn--' in input_text.lower():
            try:
                # Coba decode Punycode per bagian (jika berupa domain)
                parts = input_text.split('.')
                decoded_parts = []
                has_punycode = False
                
                for p in parts:
                    if p.lower().startswith('xn--'):
                        try:
                            # Gunakan encoding idna bawaan python
                            decoded_p = p.encode('ascii').decode('idna')
                            decoded_parts.append(decoded_p)
                            has_punycode = True
                        except:
                            decoded_parts.append(p)
                    else:
                        decoded_parts.append(p)
                
                if has_punycode:
                    punycode_info['is_punycode'] = True
                    punycode_info['decoded_text'] = '.'.join(decoded_parts)
            except Exception as e:
                print(f"Punycode decode error: {e}")

        # Apakah ada perubahan setelah konversi?
        has_homoglyphs = converted_text != input_text

        return jsonify({
            'success': True,
            'input_text': input_text,
            'converted_text': converted_text,
            'has_homoglyphs': has_homoglyphs,
            'punycode_info': punycode_info,
            'total_characters': len(all_characters),
            'cyrillic_count': len(cyrillic_only),
            'all_characters': all_characters,
            'cyrillic_only': cyrillic_only,
            'message': 'Analisis karakter Cyrillic dan Punycode berhasil'
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


def convert_to_cyrillic():
    """
    Konversi / decode text yang mengandung Cyrillic dan tampilkan detailnya.
    Input : JSON { "text": "..." }
    Output: Hasil konversi multi-encoding + detail karakter
    """
    try:
        data = request.get_json()

        if not data or 'text' not in data:
            return jsonify({
                'success': False,
                'message': 'Text field tidak boleh kosong'
            }), 400

        input_text = data.get('text', '').strip()

        if not input_text:
            return jsonify({
                'success': False,
                'message': 'Text harus diisi'
            }), 400

        # Decode dengan berbagai encoding untuk mencari Cyrillic yang benar
        encoding_results = []

        try:
            utf8_text = input_text.encode('utf-8').decode('utf-8')
            encoding_results.append({'encoding': 'UTF-8', 'text': utf8_text, 'success': True})
        except Exception:
            pass

        try:
            if isinstance(input_text, str):
                bytes_text = input_text.encode('latin-1', errors='ignore')
                cp1251_text = bytes_text.decode('cp1251', errors='ignore')
                if cp1251_text:
                    encoding_results.append({'encoding': 'Windows-1251 (CP1251)', 'text': cp1251_text, 'success': True})
        except Exception:
            pass

        # Homoglyph conversion
        converted_text = ''.join(CYRILLIC_TO_LATIN_MAP.get(c, c) for c in input_text)
        cyrillic_chars = [_char_info(c) for c in input_text if _is_cyrillic(c)]

        return jsonify({
            'success': True,
            'input_text': input_text,
            'converted_text': converted_text,
            'has_homoglyphs': converted_text != input_text,
            'encoding_results': encoding_results,
            'cyrillic_characters': cyrillic_chars,
            'message': 'Konversi dan analisis berhasil'
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


def decode_punycode():
    """
    Decode teks Punycode (xn--) kembali ke karakter Unicode asli.
    Input : JSON { "text": "xn--..." }
    """
    try:
        data = request.get_json()
        input_text = data.get('text', '').strip()

        if not input_text:
            return jsonify({'success': False, 'message': 'Text harus diisi'}), 400

        try:
            # Jika berupa domain, decode per bagian
            parts = input_text.split('.')
            decoded_parts = []
            for p in parts:
                if p.lower().startswith('xn--'):
                    decoded_parts.append(p.encode('ascii').decode('idna'))
                else:
                    decoded_parts.append(p)
            
            decoded_text = '.'.join(decoded_parts)
            return jsonify({
                'success': True,
                'input_text': input_text,
                'decoded_text': decoded_text,
                'message': 'Decoding Punycode berhasil'
            }), 200
        except Exception as e:
            return jsonify({'success': False, 'message': f'Bukan format Punycode valid: {str(e)}'}), 400

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def encode_punycode():
    """
    Encode teks Unicode ke format Punycode (xn--).
    Input : JSON { "text": "..." }
    """
    try:
        data = request.get_json()
        input_text = data.get('text', '').strip()

        if not input_text:
            return jsonify({'success': False, 'message': 'Text harus diisi'}), 400

        try:
            # Encode ke IDNA (Punycode)
            encoded_text = input_text.encode('idna').decode('ascii')
            return jsonify({
                'success': True,
                'input_text': input_text,
                'encoded_text': encoded_text,
                'message': 'Encoding Punycode berhasil'
            }), 200
        except Exception as e:
            return jsonify({'success': False, 'message': f'Gagal melakukan encoding: {str(e)}'}), 400

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
