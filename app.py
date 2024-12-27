from flask import Flask, render_template, request, jsonify
import hashlib
import multiprocessing as mp
import asyncio
import time
import string
import itertools
import random

app = Flask(__name__)

# Global değişkenler
total_attempts = 0
is_cracking = False
current_pool = None
manager = None
process_stats = None

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_md5(password):
    return hashlib.md5(password).hexdigest() if isinstance(password, bytes) else hashlib.md5(password.encode()).hexdigest()

def init_worker(shared_stats):
    global process_stats
    process_stats = shared_stats

def process_chunk(chunk, target_hash, start_attempt, process_id):
    global process_stats
    try:
        current_stats = process_stats.copy() if process_stats is not None else {}
        update_interval = 500  # Daha az güncelleme yaparak overhead'i azalt
        
        # Hash karşılaştırmaları için hedef hash'i bir kere hesapla
        target_hash = target_hash.lower()
        
        # Pre-allocate memory for batches
        BATCH_SIZE = 10000  # Daha büyük batch size
        current_batch = bytearray(BATCH_SIZE * 32)  # Pre-allocate memory
        batch_hashes = []
        
        # Hash hesaplama için optimize edilmiş fonksiyon
        md5_hash = hashlib.md5
        
        for idx, password in enumerate(chunk):
            current_attempt = start_attempt + idx
            
            # Batch işleme - direkt bytes olarak işle
            if isinstance(password, str):
                password = password.encode()
            
            # Hash hesaplama
            current_hash = md5_hash(password).hexdigest()
            
            if current_hash == target_hash:
                if process_stats is not None:
                    try:
                        with mp.Lock():
                            for pid in process_stats.keys():
                                if pid != process_id:
                                    process_stats[pid]['status'] = 'waiting'
                            
                            process_stats[process_id] = {
                                'current_password': f"FOUND! Password: {password.decode()}",
                                'attempts': current_attempt,
                                'status': 'found'
                            }
                    except Exception as e:
                        print(f"Error updating final stats: {str(e)}")
                return password, current_attempt
            
            # İstatistikleri daha seyrek güncelle
            if process_stats is not None and idx % update_interval == 0:
                try:
                    with mp.Lock():
                        current_stats[process_id] = {
                            'current_password': password.decode(),
                            'attempts': current_attempt,
                            'status': 'running'
                        }
                        process_stats.update(current_stats)
                except Exception as e:
                    print(f"Error updating stats: {str(e)}")
        
        return None, None
    except Exception as e:
        print(f"Error in process_chunk: {str(e)}")
        return None, None

async def crack_hash(hash_to_crack, max_length=16, process_multiplier=2):
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    found_password = None
    found_attempt = None
    
    # CPU optimizasyonu için ayarlar
    cpu_count = mp.cpu_count()
    optimal_process_multiplier = 8  # Process sayısını artır
    chunk_size = 200000  # Daha büyük chunk size
    
    # Windows'un process sınırlamasını aşmamak için kontrol
    max_processes = min(61, cpu_count * optimal_process_multiplier)
    process_count = max_processes
    
    print(f"CPU Cores: {cpu_count}")
    print(f"Total Processes: {process_count}")
    print(f"Chunk Size: {chunk_size}")
    
    min_length = 8
    global total_attempts, is_cracking, current_pool, process_stats
    total_attempts = 0
    is_cracking = True
    
    # Process durumlarını sıfırla
    if process_stats is not None:
        process_stats.clear()  # Yeni işlem başlatıldığında process_stats'i temizle
        for i in range(process_count):
            process_stats[i] = {
                'current_password': '',
                'attempts': 0,
                'status': 'waiting'
            }
            time.sleep(0.01)  # Her process için kısa bir bekleme
    
    def chunk_passwords(length):
        passwords = []
        for p in itertools.product(characters, repeat=length):
            password = ''.join(p)
            passwords.append(password)
            if len(passwords) >= chunk_size:
                yield passwords
                passwords = []
        if passwords:
            yield passwords

    try:
        with mp.Pool(processes=process_count, initializer=init_worker, initargs=(process_stats,)) as pool:
            current_pool = pool
            
            for length in range(min_length, max_length + 1):
                if not is_cracking:
                    print("\nCracking stopped by user")
                    break
                    
                print(f"Trying passwords of length {length}...")
                
                for chunk in chunk_passwords(length):
                    if not is_cracking:
                        break
                    
                    # Her process için ayrı chunk oluştur
                    chunk_size_per_process = max(1, len(chunk) // process_count)
                    tasks = []
                    
                    for i in range(process_count):
                        start_idx = i * chunk_size_per_process
                        end_idx = start_idx + chunk_size_per_process if i < process_count - 1 else len(chunk)
                        
                        if start_idx < len(chunk):
                            chunk_part = chunk[start_idx:end_idx]
                            tasks.append((chunk_part, hash_to_crack, total_attempts + start_idx, i))
                    
                    if tasks:
                        # Her process'i async olarak başlat
                        results = []
                        for task in tasks:
                            if not is_cracking:
                                break
                            result = pool.apply_async(process_chunk, args=task)
                            results.append(result)
                        
                        # Sonuçları bekle
                        for result in results:
                            if not is_cracking:
                                break
                            try:
                                password, attempt = result.get(timeout=1)  # 1 saniye timeout
                                if password:
                                    found_password = password
                                    found_attempt = attempt
                                    pool.terminate()
                                    break
                            except mp.TimeoutError:
                                continue
                        
                        total_attempts += sum(len(task[0]) for task in tasks)
                        
                        if found_password:
                            break
                    
                if found_password:
                    break
                    
    except Exception as e:
        print(f"Error in process pool: {str(e)}")
        raise
    finally:
        is_cracking = False
        current_pool = None
        # Process durumlarını durduruldu olarak işaretle
        if process_stats is not None:
            for pid in process_stats.keys():
                process_stats[pid] = {
                    'current_password': '',
                    'attempts': process_stats[pid]['attempts'],
                    'status': 'stopped'
                }
    
    print(f"\nCompleted with {total_attempts:,} total attempts")
    if found_password:
        print(f"Password found at attempt #{found_attempt:,}")
    return found_password, total_attempts, found_attempt

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    password = request.form.get('password')
    is_random = request.form.get('random') == 'true'
    length = int(request.form.get('length', 8))
    
    if is_random:
        password = generate_random_password(length)
    
    hash_value = generate_md5(password)
    return jsonify({
        'hash': hash_value,
        'password': password
    })

@app.route('/crack_hash', methods=['POST'])
def crack_hash_route():
    global is_cracking
    
    # Eğer zaten çalışıyorsa yeni işlem başlatma
    if is_cracking:
        return jsonify({
            'status': 'error',
            'message': 'A cracking process is already running'
        }), 400
    
    hash_to_crack = request.form.get('hash')
    max_length = int(request.form.get('max_length', 16))
    process_multiplier = int(request.form.get('process_multiplier', 2))
    
    
    if not hash_to_crack:
        return jsonify({'error': 'No hash provided'}), 400
    
    is_cracking = True
    asyncio.run(crack_hash(hash_to_crack, max_length, process_multiplier))
    
    return jsonify({
        'status': 'success',
        'message': 'Hash cracking process started'
    })

@app.route('/status')
def get_status():
    global total_attempts, process_stats, is_cracking
    
    if process_stats is None:
        return jsonify({
            'status': 'stopped',
            'attempts': 0,
            'processes': {}
        })
    
    return jsonify({
        'status': 'running' if is_cracking else 'stopped',
        'attempts': total_attempts,
        'processes': dict(process_stats)
    })

@app.route('/stop', methods=['POST'])
def stop_cracking():
    try:
        global is_cracking, current_pool
        is_cracking = False
        if current_pool:
            current_pool.terminate()
            current_pool = None
        return jsonify({
            'status': 'stopped',
            'message': 'Process successfully stopped'
        }), 200  
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    # Windows için multiprocessing desteği
    mp.freeze_support()
    manager = mp.Manager()
    process_stats = manager.dict()
    app.run(debug=True, use_reloader=False)
else:
    # Test/import durumları için
    pass
