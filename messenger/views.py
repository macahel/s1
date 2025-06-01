from django.shortcuts import render, redirect
from .models import Message
from .encryption import encrypt_message, decrypt_message

def chat_view(request):
    if request.method == "POST":
        sender = request.POST.get("sender")
        receiver = request.POST.get("receiver")
        content = request.POST.get("content")
        algorithm = request.POST.get("algorithm")
        
        # Şifreleme
        if algorithm == "None":
            encrypted_content = content
            decrypted_content = content
        else:
            encrypted_content = encrypt_message(algorithm, content)
            decrypted_content = decrypt_message(encrypted_content)
        
        # Mesajı kaydet
        Message.objects.create(
            sender=sender,
            receiver=receiver,
            content=encrypted_content,
            decrypted_content=decrypted_content,
            algorithm=algorithm
        )
        return redirect("chat")

    messages = Message.objects.all().order_by("timestamp")
    return render(request, "chat.html", {"messages": messages})