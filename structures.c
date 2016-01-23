/* 
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
  //  M->type = tgl_message_media_unsupported;
  //  break;
  case CODE_message_media_web_page:
    M->type = tgl_message_media_webpage;
    M->webpage = tglf_fetch_alloc_webpage_new (TLS, DS_MM->webpage);
    break;
  case CODE_message_media_venue:
    M->type = tgl_message_media_venue;
    tglf_fetch_geo_new (TLS, &M->venue.geo, DS_MM->geo);
    M->venue.title = DS_STR_DUP (DS_MM->title);
    M->venue.address = DS_STR_DUP (DS_MM->address);
    M->venue.provider = DS_STR_DUP (DS_MM->provider);
    M->venue.venue_id = DS_STR_DUP (DS_MM->venue_id);   
    break;
  case CODE_message_media_unsupported:
    M->type = tgl_message_media_unsupported;
    break;
  default:
    assert (0);
  }
}

void tglf_fetch_message_media_encrypted_new (struct tgl_state *TLS, struct tgl_message_media *M, struct tl_ds_decrypted_message_media *DS_DMM) {
  if (!DS_DMM) { return; }

  memset (M, 0, sizeof (*M));
  switch (DS_DMM->magic) {
  case CODE_decrypted_message_media_empty:
    M->type = tgl_message_media_none;
    //M->type = CODE_message_media_empty;
    break;
  case CODE_decrypted_message_media_photo:
  case CODE_decrypted_message_media_video:
  case CODE_decrypted_message_media_video_l12:
  case CODE_decrypted_message_media_document:
  case CODE_decrypted_message_media_audio:
    //M->type = CODE_decrypted_message_media_video;
    M->type = tgl_message_media_document_encr;
    
    M->encr_document = talloc0 (sizeof (*M->encr_document));
  
    switch (DS_DMM->magic) {
    case CODE_decrypted_message_media_photo:
      M->encr_document->flags = TGLDF_IMAGE;
      break;
    case CODE_decrypted_message_media_video:
    case CODE_decrypted_message_media_video_l12:
      M->encr_document->flags = TGLDF_VIDEO;
      break;
    case CODE_decrypted_message_media_document:
      //M->encr_document->flags = TGLDF_DOCUMENT;
      break;
    case CODE_decrypted_message_media_audio:
      M->encr_document->flags = TGLDF_AUDIO;
      break;
    }
    
    M->encr_document->w = DS_LVAL (DS_DMM->w);
    M->encr_document->h = DS_LVAL (DS_DMM->h);
    M->encr_document->size = DS_LVAL (DS_DMM->size);
    M->encr_document->duration = DS_LVAL (DS_DMM->duration);
    M->encr_document->mime_type = DS_STR_DUP (DS_DMM->mime_type);
   
    M->encr_document->key = talloc (32);
    str_to_32 (M->encr_document->key, DS_STR (DS_DMM->key));
    M->encr_document->iv = talloc (32);
    str_to_32 (M->encr_document->iv, DS_STR (DS_DMM->iv));
    break;
  case CODE_decrypted_message_media_geo_point:
    M->type = tgl_message_media_geo;
    M->geo.latitude = DS_LVAL (DS_DMM->latitude);
    M->geo.longitude = DS_LVAL (DS_DMM->longitude);
    break;
  case CODE_decrypted_message_media_contact:
    M->type = tgl_message_media_contact;
    M->phone = DS_STR_DUP (DS_DMM->phone_number);
    M->first_name = DS_STR_DUP (DS_DMM->first_name);
    M->last_name = DS_STR_DUP (DS_DMM->last_name);
    M->user_id = DS_LVAL (DS_DMM->user_id);
    break;
  default:
    assert (0);
  }
}

void tglf_fetch_message_action_encrypted_new (struct tgl_state *TLS, struct tgl_message_action *M, struct tl_ds_decrypted_message_action *DS_DMA) {
  if (!DS_DMA) { return; }
  
  switch (DS_DMA->magic) {
  case CODE_decrypted_message_action_set_message_t_t_l:
    M->type = tgl_message_action_set_message_ttl;
    M->ttl = DS_LVAL (DS_DMA->ttl_seconds);
    break;
  case CODE_decrypted_message_action_read_messages: 
    M->type = tgl_message_action_read_messages;
    { 
      M->read_cnt = DS_LVAL (DS_DMA->random_ids->cnt);
      
      int i;
      for (i = 0; i < M->read_cnt; i++) {
        struct tgl_message *N = tgl_message_get (TLS, DS_LVAL (DS_DMA->random_ids->data[i]));
        if (N) {
          N->flags &= ~TGLMF_UNREAD;
        }
      }
    }
    break;
  case CODE_decrypted_message_action_delete_messages: 
    M->type = tgl_message_action_delete_messages;
    break;
  case CODE_decrypted_message_action_screenshot_messages: 
    M->type = tgl_message_action_screenshot_messages;
    { 
      M->screenshot_cnt = DS_LVAL (DS_DMA->random_ids->cnt);
    }
    break;
  case CODE_decrypted_message_action_notify_layer: 
    M->type = tgl_message_action_notify_layer;
    M->layer = DS_LVAL (DS_DMA->layer);
    break;
  case CODE_decrypted_message_action_flush_history:
    M->type = tgl_message_action_flush_history;
    break;
  case CODE_decrypted_message_action_typing:
    M->type = tgl_message_action_typing;
    M->typing = tglf_fetch_typing_new (DS_DMA->action);
    break;
  case CODE_decrypted_message_action_resend:
    M->type = tgl_message_action_resend;
    M->start_seq_no = DS_LVAL (DS_DMA->start_seq_no);
    M->end_seq_no = DS_LVAL (DS_DMA->end_seq_no);
    break;
  case CODE_decrypted_message_action_noop:
    M->type = tgl_message_action_noop;
    break;
  case CODE_decrypted_message_action_request_key:
    M->type = tgl_message_action_request_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->g_a = talloc (256);
    str_to_256 (M->g_a, DS_STR (DS_DMA->g_a));
    break;
  case CODE_decrypted_message_action_accept_key:
    M->type = tgl_message_action_accept_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->g_a = talloc (256);
    str_to_256 (M->g_a, DS_STR (DS_DMA->g_b));
    M->key_fingerprint = DS_LVAL (DS_DMA->key_fingerprint);
    break;
  case CODE_decrypted_message_action_commit_key:
    M->type = tgl_message_action_commit_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->key_fingerprint = DS_LVAL (DS_DMA->key_fingerprint);
    break;
  case CODE_decrypted_message_action_abort_key:
    M->type = tgl_message_action_abort_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    break;
  default:
    assert (0);
  }
}

tgl_peer_id_t tglf_fetch_peer_id_new (struct tgl_state *TLS, struct tl_ds_peer *DS_P) {
  if (DS_P->magic == CODE_peer_user) {
    return TGL_MK_USER (DS_LVAL (DS_P->user_id));
  } else {
    return TGL_MK_CHAT (DS_LVAL (DS_P->chat_id));
  }
}

void tglf_fetch_message_new (struct tgl_state *TLS, struct tgl_message *M, struct tl_ds_message *DS_M) {
  if (!DS_M || DS_M->magic == CODE_message_empty) { return; }
  
  assert (M->id == DS_LVAL (DS_M->id));
  
  tgl_peer_id_t to_id = tglf_fetch_peer_id_new (TLS, DS_M->to_id);
  {
    tgl_peer_t *P = tgl_peer_get (TLS, to_id);
    if (!P || !(P->flags & TGLPF_CREATED)) {
      tgl_do_get_difference (TLS, 0, 0, 0);
      return;
    }
    P = tgl_peer_get (TLS, TGL_MK_USER (DS_LVAL (DS_M->from_id)));
    if (!P || !(P->flags & TGLPF_CREATED)) {
      tgl_do_get_difference (TLS, 0, 0, 0);
      return;
    }
  }

  int new = !(M->flags & TGLMF_CREATED);

  if (new) {
    int peer_id = tgl_get_peer_id (to_id);
    int peer_type = tgl_get_peer_type (to_id);

    int flags = 0;
    if (DS_LVAL (DS_M->flags) & 1) {
      flags |= TGLMF_UNREAD;
    }
    if (DS_LVAL (DS_M->flags) & 2) {
      flags |= TGLMF_OUT;
    }
    if (DS_LVAL (DS_M->flags) & 16) {
      flags |= TGLMF_MENTION;
    }

    bl_do_create_message_new (TLS, DS_LVAL (DS_M->id),
      DS_M->from_id,
      &peer_type, &peer_id,
      DS_M->fwd_from_id, DS_M->fwd_date,
      DS_M->date,
      DS_STR (DS_M->message),
      DS_M->media,
      DS_M->action,
      DS_M->reply_to_msg_id,
      DS_M->reply_markup,
      flags | TGLMF_CREATE | TGLMF_CREATED
    );
  }
}

static int *decr_ptr;
static int *decr_end;

static int decrypt_encrypted_message (struct tgl_secret_chat *E) {
  int *msg_key = decr_ptr;
  decr_ptr += 4;
  assert (decr_ptr < decr_end);
  static unsigned char sha1a_buffer[20];
  static unsigned char sha1b_buffer[20];
  static unsigned char sha1c_buffer[20];
  static unsigned char sha1d_buffer[20];
 
  static unsigned char buf[64];

  int *e_key = E->exchange_state != tgl_sce_committed ? E->key : E->exchange_key;

  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, e_key, 32);
  sha1 (buf, 48, sha1a_buffer);
  
  memcpy (buf, e_key + 8, 16);
  memcpy (buf + 16, msg_key, 16);
  memcpy (buf + 32, e_key + 12, 16);
  sha1 (buf, 48, sha1b_buffer);
  
  memcpy (buf, e_key + 16, 32);
  memcpy (buf + 32, msg_key, 16);
  sha1 (buf, 48, sha1c_buffer);
  
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, e_key + 24, 32);
  sha1 (buf, 48, sha1d_buffer);

  static unsigned char key[32];
  memcpy (key, sha1a_buffer + 0, 8);
  memcpy (key + 8, sha1b_buffer + 8, 12);
  memcpy (key + 20, sha1c_buffer + 4, 12);

  static unsigned char iv[32];
  memcpy (iv, sha1a_buffer + 8, 12);
  memcpy (iv + 12, sha1b_buffer + 0, 8);
  memcpy (iv + 20, sha1c_buffer + 16, 4);
  memcpy (iv + 24, sha1d_buffer + 0, 8);

  AES_KEY aes_key;
  AES_set_decrypt_key (key, 256, &aes_key);
  AES_ige_encrypt ((void *)decr_ptr, (void *)decr_ptr, 4 * (decr_end - decr_ptr), &aes_key, iv, 0);
  memset (&aes_key, 0, sizeof (aes_key));

  int x = *(decr_ptr);
  if (x < 0 || (x & 3)) {
    return -1;
  }
  assert (x >= 0 && !(x & 3));
  sha1 ((void *)decr_ptr, 4 + x, sha1a_buffer);

  if (memcmp (sha1a_buffer + 4, msg_key, 16)) {
    return -1;
  }
  return 0;
}

void tglf_fetch_encrypted_message_new (struct tgl_state *TLS, struct tgl_message *M, struct tl_ds_encrypted_message *DS_EM) {
  if (!DS_EM) { return; }

  int new = !(M->flags & TGLMF_CREATED);
  if (!new) {
    return;
  }
  
  tgl_peer_t *P = tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (DS_LVAL (DS_EM->chat_id)));
  if (!P || P->encr_chat.state != sc_ok) {
    vlogprintf (E_WARNING, "Encrypted message to unknown chat. Dropping\n");
    return;
  }

  decr_ptr = (void *)DS_EM->bytes->data;
  decr_end = decr_ptr + (DS_EM->bytes->len / 4);
  
  if (P->encr_chat.exchange_state == tgl_sce_committed && P->encr_chat.key_fingerprint == *(long long *)decr_ptr) {
    tgl_do_confirm_exchange (TLS, (void *)P, 0);
    assert (P->encr_chat.exchange_state == tgl_sce_none);
  }
  
  long long key_fingerprint = P->encr_chat.exchange_state != tgl_sce_committed ? P->encr_chat.key_fingerprint : P->encr_chat.exchange_key_fingerprint;
  if (*(long long *)decr_ptr != key_fingerprint) {
    vlogprintf (E_WARNING, "Encrypted message with bad fingerprint to chat %s\n", P->print_name);
    return;
  }
  
  decr_ptr += 2;

  if (decrypt_encrypted_message (&P->encr_chat) < 0) {
    vlogprintf (E_WARNING, "can not decrypt message\n");
    return;
  }
  
  int *save_in_ptr = in_ptr;
  int *save_in_end = in_end;
    
  in_ptr = decr_ptr;
  int ll = *in_ptr;
  in_end = in_ptr + ll / 4 + 1;  
  assert (fetch_int () == ll);

  if (skip_type_decrypted_message_layer (TYPE_TO_PARAM (decrypted_message_layer)) < 0 || in_ptr != in_end) {
    vlogprintf (E_WARNING, "can not fetch message\n");
    in_ptr = save_in_ptr;
    in_end = save_in_end;
    return;
  }

  in_ptr = decr_ptr;
  assert (fetch_int () == ll);

  struct tl_ds_decrypted_message_layer *DS_DML = fetch_ds_type_decrypted_message_layer (TYPE_TO_PARAM (decrypted_message_layer));
  assert (DS_DML);

  in_ptr = save_in_ptr;
  in_end = save_in_end;

  //bl_do_encr_chat_set_layer (TLS, (void *)P, DS_LVAL (DS_DML->layer));
  bl_do_encr_chat_new (TLS, tgl_get_peer_id (P->id),
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, DS_DML->layer, NULL, NULL, NULL, NULL,
    TGL_FLAGS_UNCHANGED
  );

  int in_seq_no = DS_LVAL (DS_DML->out_seq_no);
  int out_seq_no = DS_LVAL (DS_DML->in_seq_no);

  if (in_seq_no / 2 != P->encr_chat.in_seq_no) {
    vlogprintf (E_WARNING, "Hole in seq in secret chat. in_seq_no = %d, expect_seq_no = %d\n", in_seq_no / 2, P->encr_chat.in_seq_no);
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return;
  }
  
  if ((in_seq_no & 1)  != 1 - (P->encr_chat.admin_id == TLS->our_id) || 
      (out_seq_no & 1) != (P->encr_chat.admin_id == TLS->our_id)) {
    vlogprintf (E_WARNING, "Bad msg admin\n");
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return;
  }
  if (out_seq_no / 2 > P->encr_chat.out_seq_no) {
    vlogprintf (E_WARNING, "In seq no is bigger than our's out seq no (out_seq_no = %d, our_out_seq_no = %d). Drop\n", out_seq_no / 2, P->encr_chat.out_seq_no);
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return;
  }
  if (out_seq_no / 2 < P->encr_chat.last_in_seq_no) {
    vlogprintf (E_WARNING, "Clients in_seq_no decreased (out_seq_no = %d, last_out_seq_no = %d). Drop\n", out_seq_no / 2, P->encr_chat.last_in_seq_no);
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return;
  }

  struct tl_ds_decrypted_message *DS_DM = DS_DML->message;
  if (M->id != DS_LVAL (DS_DM->random_id)) {
    vlogprintf (E_ERROR, "Incorrect message: id = %lld, new_id = %lld\n", M->id, DS_LVAL (DS_DM->random_id));
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return;
  }
  
  int peer_type = TGL_PEER_ENCR_CHAT;
  int peer_id = tgl_get_peer_id (P->id);

  bl_do_create_message_encr_new (TLS, M->id, &P->encr_chat.user_id, &peer_type, &peer_id, DS_EM->date, DS_STR (DS_DM->message), DS_DM->media, DS_DM->action, DS_EM->file, TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED);

  if (in_seq_no >= 0 && out_seq_no >= 0) {
    //bl_do_encr_chat_update_seq (TLS, (void *)P, in_seq_no / 2 + 1, out_seq_no / 2);
    in_seq_no = in_seq_no / 2 + 1;
    out_seq_no = out_seq_no / 2;
    bl_do_encr_chat_new (TLS, tgl_get_peer_id (P->id),
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, &in_seq_no, &out_seq_no, NULL, NULL,
      TGL_FLAGS_UNCHANGED
    );
    assert (P->encr_chat.in_seq_no == in_seq_no);
  }
  
  free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
}

void tglf_fetch_encrypted_message_file_new (struct tgl_state *TLS, struct tgl_message_media *M, struct tl_ds_encrypted_file *DS_EF) {
  if (DS_EF->magic == CODE_encrypted_file_empty) {
    assert (M->type != tgl_message_media_document_encr);
  } else {
    assert (M->type == tgl_message_media_document_encr);
    assert (M->encr_document);

    M->encr_document->id = DS_LVAL (DS_EF->id);
    M->encr_document->access_hash = DS_LVAL (DS_EF->access_hash);
    if (!M->encr_document->size) {
      M->encr_document->size = DS_LVAL (DS_EF->size);
    }
    M->encr_document->dc_id = DS_LVAL (DS_EF->dc_id);
    M->encr_document->key_fingerprint = DS_LVAL (DS_EF->key_fingerprint);
  }
}

static int id_cmp (struct tgl_message *M1, struct tgl_message *M2) {
  if (M1->id < M2->id) { return -1; }
  else if (M1->id > M2->id) { return 1; }
  else { return 0; }
}

static void increase_peer_size (struct tgl_state *TLS) {
  if (TLS->peer_num == TLS->peer_size) {
    int new_size = TLS->peer_size ? 2 * TLS->peer_size : 10;
    int old_size = TLS->peer_size;
    if (old_size) {
      TLS->Peers = trealloc (TLS->Peers, old_size * sizeof (void *), new_size * sizeof (void *));
    } else {
      TLS->Peers = talloc (new_size * sizeof (void *));
    }
    TLS->peer_size = new_size;
  }
}

struct tgl_user *tglf_fetch_alloc_user_new (struct tgl_state *TLS, struct tl_ds_user *DS_U) {
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_USER (DS_LVAL (DS_U->id)));
  if (!U) {
    TLS->users_allocated ++;
    U = talloc0 (sizeof (*U));
    U->id = TGL_MK_USER (DS_LVAL (DS_U->id));
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, U, lrand48 ());
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = U;
  }
  tglf_fetch_user_new (TLS, &U->user, DS_U);
  return &U->user;
}

struct tgl_secret_chat *tglf_fetch_alloc_encrypted_chat_new (struct tgl_state *TLS, struct tl_ds_encrypted_chat *DS_EC) {
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (DS_LVAL (DS_EC->id)));
  if (!U) {
    U = talloc0 (sizeof (*U));
    U->id = TGL_MK_ENCR_CHAT (DS_LVAL (DS_EC->id));
    TLS->encr_chats_allocated ++;
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, U, lrand48 ());
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = U;
  }
  tglf_fetch_encrypted_chat_new (TLS, &U->encr_chat, DS_EC);
  return &U->encr_chat;
}

struct tgl_user *tglf_fetch_alloc_user_full_new (struct tgl_state *TLS, struct tl_ds_user_full *DS_U) {
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_USER (DS_LVAL (DS_U->user->id)));
  if (U) {
    tglf_fetch_user_full_new (TLS, &U->user, DS_U);
    return &U->user;
  } else {
    TLS->users_allocated ++;
    U = talloc0 (sizeof (*U));
    U->id = TGL_MK_USER (DS_LVAL (DS_U->user->id));
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, U, lrand48 ());
    tglf_fetch_user_full_new (TLS, &U->user, DS_U);
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = U;
    return &U->user;
  }
}

struct tgl_message *tglf_fetch_alloc_message_new (struct tgl_state *TLS, struct tl_ds_message *DS_M) {
  struct tgl_message *M = tgl_message_get (TLS, DS_LVAL (DS_M->id));

  if (!M) {
    M = tglm_message_alloc (TLS, DS_LVAL (DS_M->id));
  }
  tglf_fetch_message_new (TLS, M, DS_M);
  return M;
}

struct tgl_message *tglf_fetch_alloc_encrypted_message_new (struct tgl_state *TLS, struct tl_ds_encrypted_message *DS_EM) {
  struct tgl_message *M = tgl_message_get (TLS, DS_LVAL (DS_EM->random_id));

  if (!M) {
    M = talloc0 (sizeof (*M));
    M->id = DS_LVAL (DS_EM->random_id);
    tglm_message_insert_tree (TLS, M);
    TLS->messages_allocated ++;
    assert (tgl_message_get (TLS, M->id) == M);
  }
  tglf_fetch_encrypted_message_new (TLS, M, DS_EM);

  if (M->flags & TGLMF_CREATED) {
    tgl_peer_t *_E = tgl_peer_get (TLS, M->to_id);
    assert (_E);
    struct tgl_secret_chat *E = &_E->encr_chat;
    if (M->action.type == tgl_message_action_request_key) {
      if (E->exchange_state == tgl_sce_none || (E->exchange_state == tgl_sce_requested && E->exchange_id > M->action.exchange_id )) {
        tgl_do_accept_exchange (TLS, E, M->action.exchange_id, M->action.g_a);
      } else {
        vlogprintf (E_WARNING, "Exchange: Incorrect state (received request, state = %d)\n", E->exchange_state);
      }
    }
    if (M->action.type == tgl_message_action_accept_key) {
      if (E->exchange_state == tgl_sce_requested && E->exchange_id == M->action.exchange_id) {
        tgl_do_commit_exchange (TLS, E, M->action.g_a);
      } else {
        vlogprintf (E_WARNING, "Exchange: Incorrect state (received accept, state = %d)\n", E->exchange_state);
      }
    }
    if (M->action.type == tgl_message_action_commit_key) {
      if (E->exchange_state == tgl_sce_accepted && E->exchange_id == M->action.exchange_id) {
        tgl_do_confirm_exchange (TLS, E, 1);
      } else {
        vlogprintf (E_WARNING, "Exchange: Incorrect state (received commit, state = %d)\n", E->exchange_state);
      }
    }
    if (M->action.type == tgl_message_action_abort_key) {
      if (E->exchange_state != tgl_sce_none && E->exchange_id == M->action.exchange_id) {
        tgl_do_abort_exchange (TLS, E);
      } else {
        vlogprintf (E_WARNING, "Exchange: Incorrect state (received abort, state = %d)\n", E->exchange_state);
      }
    }
    if (M->action.type == tgl_message_action_notify_layer) {
      bl_do_encr_chat_new (TLS, tgl_get_peer_id (E->id),
        NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL,
        NULL, &M->action.layer, NULL, NULL, NULL, NULL,
        TGL_FLAGS_UNCHANGED
      );
    }
    if (M->action.type == tgl_message_action_set_message_ttl) {
      //bl_do_encr_chat_set_ttl (TLS, E, M->action.ttl);      
      bl_do_encr_chat_new (TLS, tgl_get_peer_id (E->id),
        NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL,
        &M->action.ttl, NULL, NULL, NULL, NULL, NULL,
        TGL_FLAGS_UNCHANGED
      );
    }
  }
  return M;
}

struct tgl_message *tglf_fetch_alloc_message_short_new (struct tgl_state *TLS, struct tl_ds_updates *DS_U) {
  int id = DS_LVAL (DS_U->id);
  struct tgl_message *M = tgl_message_get (TLS, id);

  if (!M) {
    M = talloc0 (sizeof (*M));
    M->id = id;
    tglm_message_insert_tree (TLS, M);
    TLS->messages_allocated ++;
  }
  tglf_fetch_message_short_new (TLS, M, DS_U);
  return M;
}

struct tgl_message *tglf_fetch_alloc_message_short_chat_new (struct tgl_state *TLS, struct tl_ds_updates *DS_U) {
  int id = DS_LVAL (DS_U->id);
  struct tgl_message *M = tgl_message_get (TLS, id);

  if (!M) {
    M = talloc0 (sizeof (*M));
    M->id = id;
    tglm_message_insert_tree (TLS, M);
    TLS->messages_allocated ++;
  }
  tglf_fetch_message_short_chat_new (TLS, M, DS_U);
  return M;
}

struct tgl_chat *tglf_fetch_alloc_chat_new (struct tgl_state *TLS, struct tl_ds_chat *DS_C) {
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_CHAT (DS_LVAL (DS_C->id)));
  if (!U) {
    TLS->chats_allocated ++;
    U = talloc0 (sizeof (*U));
    U->id = TGL_MK_CHAT (DS_LVAL (DS_C->id));
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, U, lrand48 ());
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = U;
  }
  tglf_fetch_chat_new (TLS, &U->chat, DS_C);
  return &U->chat;
}

struct tgl_chat *tglf_fetch_alloc_chat_full_new (struct tgl_state *TLS, struct tl_ds_messages_chat_full *DS_MCF) {
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_CHAT (DS_LVAL (DS_MCF->full_chat->id)));
  if (U) {
    tglf_fetch_chat_full_new (TLS, &U->chat, DS_MCF);
    return &U->chat;
  } else {
    TLS->chats_allocated ++;
    U = talloc0 (sizeof (*U));
    U->id = TGL_MK_CHAT (DS_LVAL (DS_MCF->full_chat->id));
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, U, lrand48 ());
    tglf_fetch_chat_full_new (TLS, &U->chat, DS_MCF);
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = U;
    return &U->chat;
  }
}

struct tgl_bot_info *tglf_fetch_alloc_bot_info (struct tgl_state *TLS, struct tl_ds_bot_info *DS_BI) {
  if (!DS_BI || DS_BI->magic == CODE_bot_info_empty) { return NULL; }
  struct tgl_bot_info *B = talloc (sizeof (*B));
  B->version = DS_LVAL (DS_BI->version);
  B->share_text = DS_STR_DUP (DS_BI->share_text);
  B->description = DS_STR_DUP (DS_BI->description);

  B->commands_num = DS_LVAL (DS_BI->commands->cnt);
  B->commands = talloc (sizeof (struct tgl_bot_command) * B->commands_num);
  int i;
  for (i = 0; i < B->commands_num; i++) {
    struct tl_ds_bot_command *BC = DS_BI->commands->data[i];
    B->commands[i].command = DS_STR_DUP (BC->command);
    B->commands[i].description = DS_STR_DUP (BC->description);
  }
  return B;
}

struct tgl_message_reply_markup *tglf_fetch_alloc_reply_markup (struct tgl_state *TLS, struct tgl_message *M, struct tl_ds_reply_markup *DS_RM) {
  if (!DS_RM) { return NULL; }

  struct tgl_message_reply_markup *R = talloc0 (sizeof (*R));
  R->flags = DS_LVAL (DS_RM->flags);
  R->refcnt = 1;

  R->rows = DS_RM->rows ? DS_LVAL (DS_RM->rows->cnt) : 0;

  int total = 0;
  R->row_start = talloc ((R->rows + 1) * 4);
  R->row_start[0] = 0;
  int i;
  for (i = 0; i < R->rows; i++) {
    struct tl_ds_keyboard_button_row *DS_K = DS_RM->rows->data[i];
    total += DS_LVAL (DS_K->buttons->cnt);
    R->row_start[i + 1] = total;
  }
  R->buttons = talloc (sizeof (void *) * total);
  int r = 0;
  for (i = 0; i < R->rows; i++) {
    struct tl_ds_keyboard_button_row *DS_K = DS_RM->rows->data[i];
    int j;
    for (j = 0; j < DS_LVAL (DS_K->buttons->cnt); j++) {
      struct tl_ds_keyboard_button *DS_KB = DS_K->buttons->data[j];
      R->buttons[r ++] = DS_STR_DUP (DS_KB->text);
    }
  }
  assert (r == total);
  return R;
}
/* }}} */

void tglp_insert_encrypted_chat (struct tgl_state *TLS, tgl_peer_t *P) {
  TLS->encr_chats_allocated ++;
  TLS->peer_tree = tree_insert_peer (TLS->peer_tree, P, lrand48 ());
  increase_peer_size (TLS);
  TLS->Peers[TLS->peer_num ++] = P;
}

void tglp_insert_user (struct tgl_state *TLS, tgl_peer_t *P) {
  TLS->users_allocated ++;
  TLS->peer_tree = tree_insert_peer (TLS->peer_tree, P, lrand48 ());
  increase_peer_size (TLS);
  TLS->Peers[TLS->peer_num ++] = P;
}

void tglp_insert_chat (struct tgl_state *TLS, tgl_peer_t *P) {
  TLS->chats_allocated ++;
  TLS->peer_tree = tree_insert_peer (TLS->peer_tree, P, lrand48 ());
  increase_peer_size (TLS);
  TLS->Peers[TLS->peer_num ++] = P;
}

void tgl_insert_empty_user (struct tgl_state *TLS, int uid) {
  tgl_peer_id_t id = TGL_MK_USER (uid);
  if (tgl_peer_get (TLS, id)) { return; }
  tgl_peer_t *P = talloc0 (sizeof (*P));
  P->id = id;
  tglp_insert_user (TLS, P);
}

void tgl_insert_empty_chat (struct tgl_state *TLS, int cid) {
  tgl_peer_id_t id = TGL_MK_CHAT (cid);
  if (tgl_peer_get (TLS, id)) { return; }
  tgl_peer_t *P = talloc0 (sizeof (*P));
  P->id = id;
  tglp_insert_chat (TLS, P);
}

/* {{{ Free */

void tgls_free_photo_size (struct tgl_state *TLS, struct tgl_photo_size *S) {
  tfree_str (S->type);
  if (S->data) {
    tfree (S->data, S->size);
  }
}

void tgls_free_photo (struct tgl_state *TLS, struct tgl_photo *P) {
  if (--P->refcnt) {
    assert (P->refcnt > 0);
    return;
  }
  if (P->caption) { tfree_str (P->caption); }
  if (P->sizes) {
    int i;
    for (i = 0; i < P->sizes_num; i++) {
      tgls_free_photo_size (TLS, &P->sizes[i]);
    }
    tfree (P->sizes, sizeof (struct tgl_photo_size) * P->sizes_num);
  }
  TLS->photo_tree = tree_delete_photo (TLS->photo_tree, P);
  tfree (P, sizeof (*P));
}

void tgls_free_document (struct tgl_state *TLS, struct tgl_document *D) {
  if (--D->refcnt) {
    assert (D->refcnt);
    return;
  }
  if (D->mime_type) { tfree_str (D->mime_type);}
  if (D->caption) {tfree_str (D->caption);}
  tgls_free_photo_size (TLS, &D->thumb);
  
  TLS->document_tree = tree_delete_document (TLS->document_tree, D);
  tfree (D, sizeof (*D));
}

void tgls_free_webpage (struct tgl_state *TLS, struct tgl_webpage *W) {
  if (--W->refcnt) {
    assert (W->refcnt);
    return;
  }
  if (W->url) { tfree_str (W->url); }
  if (W->display_url) { tfree_str (W->display_url); }
  if (W->title) { tfree_str (W->title); }
  if (W->site_name) { tfree_str (W->site_name); }
  if (W->type) { tfree_str (W->type); }
  if (W->description) { tfree_str (W->description); }
  if (W->photo) { tgls_free_photo (TLS, W->photo); }
  if (W->embed_url) { tfree_str (W->embed_url); }
  if (W->embed_type) { tfree_str (W->embed_type); }
  if (W->author) { tfree_str (W->author); }
  
  TLS->webpage_tree = tree_delete_webpage (TLS->webpage_tree, W);
  tfree (W, sizeof (*W));
}

void tgls_free_message_media (struct tgl_state *TLS, struct tgl_message_media *M) {
  switch (M->type) {
  case tgl_message_media_none:
  case tgl_message_media_geo:
    return;
  case tgl_message_media_photo:
    tgls_free_photo (TLS, M->photo);
    M->photo = NULL;
    return;
  case tgl_message_media_contact:
    tfree_str (M->phone);
    tfree_str (M->first_name);
    tfree_str (M->last_name);
    return;
  case tgl_message_media_document:
  case tgl_message_media_video:
  case tgl_message_media_audio:
    tgls_free_document (TLS, M->document);
    return;
  case tgl_message_media_unsupported:
    tfree (M->data, M->data_size);
    return;
  case tgl_message_media_document_encr:
    tfree_secure (M->encr_document->key, 32);
    tfree_secure (M->encr_document->iv, 32);
    tfree (M->encr_document, sizeof (*M->encr_document));
    return;
  case tgl_message_media_webpage:
    tgls_free_webpage (TLS, M->webpage);
    return;
  case tgl_message_media_venue:
    if (M->venue.title) { tfree_str (M->venue.title); }
    if (M->venue.address) { tfree_str (M->venue.address); }
    if (M->venue.provider) { tfree_str (M->venue.provider); }
    if (M->venue.venue_id) { tfree_str (M->venue.venue_id); }
    return;
  default:
    vlogprintf (E_ERROR, "type = 0x%08x\n", M->type);
    assert (0);
  }
}

void tgls_free_message_action (struct tgl_state *TLS, struct tgl_message_action *M) {
  switch (M->type) {
  case tgl_message_action_none:
    return;
  case tgl_message_action_chat_create:
    tfree_str (M->title);
    tfree (M->users, M->user_num * 4);
    return;
  case tgl_message_action_chat_edit_title:
    tfree_str (M->new_title);
    return;
  case tgl_message_action_chat_edit_photo:
    tgls_free_photo (TLS, M->photo);
    M->photo = NULL;
    return;
  case tgl_message_action_chat_delete_photo:
  case tgl_message_action_chat_add_user:
  case tgl_message_action_chat_add_user_by_link:
  case tgl_message_action_chat_delete_user:
  case tgl_message_action_geo_chat_create:
  case tgl_message_action_geo_chat_checkin:
  case tgl_message_action_set_message_ttl:
  case tgl_message_action_read_messages:
  case tgl_message_action_delete_messages:
  case tgl_message_action_screenshot_messages:
  case tgl_message_action_flush_history:
  case tgl_message_action_typing:
  case tgl_message_action_resend:
  case tgl_message_action_notify_layer:
  case tgl_message_action_commit_key:
  case tgl_message_action_abort_key:
  case tgl_message_action_noop:
    return;
  case tgl_message_action_request_key:
  case tgl_message_action_accept_key:
    tfree (M->g_a, 256);
    return;
/*  default:
    vlogprintf (E_ERROR, "type = 0x%08x\n", M->type);
    assert (0);*/
  }
  vlogprintf (E_ERROR, "type = 0x%08x\n", M->type);
  assert (0);
}

void tgls_clear_message (struct tgl_state *TLS, struct tgl_message *M) {
  if (!(M->flags & TGLMF_SERVICE)) {
    if (M->message) { tfree (M->message, M->message_len + 1); }
    tgls_free_message_media (TLS, &M->media);
  } else {
    tgls_free_message_action (TLS, &M->action);
  }
}

void tgls_free_reply_markup (struct tgl_state *TLS, struct tgl_message_reply_markup *R) { 
  if (!--R->refcnt) {
    tfree (R->buttons, R->row_start[R->rows] * sizeof (void *));
    tfree (R->row_start, 4 * (R->rows + 1));
    tfree (R, sizeof (*R));
  } else {
    assert (R->refcnt > 0);
  }
}

void tgls_free_message (struct tgl_state *TLS, struct tgl_message *M) {
  tgls_clear_message (TLS, M);
  if (M->reply_markup) {
    tgls_free_reply_markup (TLS, M->reply_markup);
  }
  tfree (M, sizeof (*M));
}

void tgls_free_chat (struct tgl_state *TLS, struct tgl_chat *U) {
  if (U->title) { tfree_str (U->title); }
  if (U->print_title) { tfree_str (U->print_title); }
  if (U->user_list) {
    tfree (U->user_list, U->user_list_size * 12);
  }
  if (U->photo) { tgls_free_photo (TLS, U->photo); }
  tfree (U, sizeof (*U));
}

void tgls_free_user (struct tgl_state *TLS, struct tgl_user *U) {
  if (U->first_name) { tfree_str (U->first_name); }
  if (U->last_name) { tfree_str (U->last_name); }
  if (U->print_name) { tfree_str (U->print_name); }
  if (U->phone) { tfree_str (U->phone); }
  if (U->real_first_name) { tfree_str (U->real_first_name); }
  if (U->real_last_name) { tfree_str (U->real_last_name); }
  if (U->status.ev) { tgl_remove_status_expire (TLS, U); }
  if (U->photo) { tgls_free_photo (TLS, U->photo); }
  tfree (U, sizeof (*U));
}

void tgls_free_encr_chat (struct tgl_state *TLS, struct tgl_secret_chat *U) {
  if (U->print_name) { tfree_str (U->print_name); }
  if (U->g_key) { tfree (U->g_key, 256); } 
  tfree (U, sizeof (*U));
}

void tgls_free_peer (struct tgl_state *TLS, tgl_peer_t *P) {
  if (tgl_get_peer_type (P->id) == TGL_PEER_USER) {
    tgls_free_user (TLS, (void *)P);
  } else if (tgl_get_peer_type (P->id) == TGL_PEER_CHAT) {
    tgls_free_chat (TLS, (void *)P);
  } else if (tgl_get_peer_type (P->id) == TGL_PEER_ENCR_CHAT) {
    tgls_free_encr_chat (TLS, (void *)P);
  } else {
    assert (0);
  }
}

void tgls_free_bot_info (struct tgl_state *TLS, struct tgl_bot_info *B) {
  if (!B) { return; }
  int i;
  for (i = 0; i < B->commands_num; i++) {
    tfree_str (B->commands[i].command);
    tfree_str (B->commands[i].description);
  }
  tfree (B->commands, sizeof (struct tgl_bot_command) * B->commands_num);
  tfree_str (B->share_text);
  tfree_str (B->description);
  tfree (B, sizeof (*B));
}
/* }}} */

/* Messages {{{ */

void tglm_message_del_use (struct tgl_state *TLS, struct tgl_message *M) {
  M->next_use->prev_use = M->prev_use;
  M->prev_use->next_use = M->next_use;
}

void tglm_message_add_use (struct tgl_state *TLS, struct tgl_message *M) {
  M->next_use = TLS->message_list.next_use;
  M->prev_use = &TLS->message_list;
  M->next_use->prev_use = M;
  M->prev_use->next_use = M;
}

void tglm_message_add_peer (struct tgl_state *TLS, struct tgl_message *M) {
  tgl_peer_id_t id;
  if (!tgl_cmp_peer_id (M->to_id, TGL_MK_USER (TLS->our_id))) {
    id = M->from_id;
  } else {
    id = M->to_id;
  }
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P) {
    P = talloc0 (sizeof (*P));
    P->id = id;
    switch (tgl_get_peer_type (id)) {
    case TGL_PEER_USER:
      TLS->users_allocated ++;
      break;
    case TGL_PEER_CHAT:
      TLS->chats_allocated ++;
      break;
    case TGL_PEER_GEO_CHAT:
      TLS->geo_chats_allocated ++;
      break;
    case TGL_PEER_ENCR_CHAT:
      TLS->encr_chats_allocated ++;
      break;
    }
    TLS->peer_tree = tree_insert_peer (TLS->peer_tree, P, lrand48 ());
    increase_peer_size (TLS);
    TLS->Peers[TLS->peer_num ++] = P;
  }
  if (!P->last) {
    P->last = M;
    M->prev = M->next = 0;
  } else {
    if (tgl_get_peer_type (P->id) != TGL_PEER_ENCR_CHAT) {
      struct tgl_message *N = P->last;
      struct tgl_message *NP = 0;
      while (N && N->id > M->id) {
        NP = N;
        N = N->next;
      }
      if (N) {
        assert (N->id < M->id); 
      }
      M->next = N;
      M->prev = NP;
      if (N) { N->prev = M; }
      if (NP) { NP->next = M; }
      else { P->last = M; }
    } else {
      struct tgl_message *N = P->last;
      struct tgl_message *NP = 0;
      M->next = N;
      M->prev = NP;
      if (N) { N->prev = M; }
      if (NP) { NP->next = M; }
      else { P->last = M; }
    }
  }
}

void tglm_message_del_peer (struct tgl_state *TLS, struct tgl_message *M) {
  tgl_peer_id_t id;
  if (!tgl_cmp_peer_id (M->to_id, TGL_MK_USER (TLS->our_id))) {
    id = M->from_id;
  } else {
    id = M->to_id;
  }
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (M->prev) {
    M->prev->next = M->next;
  }
  if (M->next) {
    M->next->prev = M->prev;
  }
  if (P && P->last == M) {
    P->last = M->next;
  }
}

struct tgl_message *tglm_message_alloc (struct tgl_state *TLS, long long id) {
  struct tgl_message *M = talloc0 (sizeof (*M));
  M->id = id;
  tglm_message_insert_tree (TLS, M);
  TLS->messages_allocated ++;
  return M;
}

void tglm_message_insert_tree (struct tgl_state *TLS, struct tgl_message *M) {
  assert (M->id);
  TLS->message_tree = tree_insert_message (TLS->message_tree, M, lrand48 ());
}

void tglm_message_remove_tree (struct tgl_state *TLS, struct tgl_message *M) {
  assert (M->id);
  TLS->message_tree = tree_delete_message (TLS->message_tree, M);
}

void tglm_message_insert (struct tgl_state *TLS, struct tgl_message *M) {
  tglm_message_add_use (TLS, M);
  tglm_message_add_peer (TLS, M);
}

void tglm_message_insert_unsent (struct tgl_state *TLS, struct tgl_message *M) {
  TLS->message_unsent_tree = tree_insert_message (TLS->message_unsent_tree, M, lrand48 ());
}

void tglm_message_remove_unsent (struct tgl_state *TLS, struct tgl_message *M) {
  TLS->message_unsent_tree = tree_delete_message (TLS->message_unsent_tree, M);
}

static void __send_msg (struct tgl_message *M, void *_TLS) {
  struct tgl_state *TLS = _TLS;
  vlogprintf (E_NOTICE, "Resending message...\n");
  //print_message (M);

  if (M->media.type != tgl_message_media_none) {
    assert (M->flags & TGLMF_ENCRYPTED);
    bl_do_message_delete (TLS, M);
  } else {
    tgl_do_send_msg (TLS, M, 0, 0);
  }
}

void tglm_send_all_unsent (struct tgl_state *TLS) {
  tree_act_ex_message (TLS->message_unsent_tree, __send_msg, TLS);
}
/* }}} */

struct tgl_photo *tgl_photo_get (struct tgl_state *TLS, long long id) {
  struct tgl_photo P;
  P.id = id;
  return tree_lookup_photo (TLS->photo_tree, &P);
}

void tgl_photo_insert (struct tgl_state *TLS, struct tgl_photo *P) {
  TLS->photo_tree = tree_insert_photo (TLS->photo_tree, P, lrand48 ());
}

struct tgl_document *tgl_document_get (struct tgl_state *TLS, long long id) {
  struct tgl_document P;
  P.id = id;
  return tree_lookup_document (TLS->document_tree, &P);
}

void tgl_document_insert (struct tgl_state *TLS, struct tgl_document *P) {
  TLS->document_tree = tree_insert_document (TLS->document_tree, P, lrand48 ());
}

struct tgl_webpage *tgl_webpage_get (struct tgl_state *TLS, long long id) {
  struct tgl_webpage P;
  P.id = id;
  return tree_lookup_webpage (TLS->webpage_tree, &P);
}

void tgl_webpage_insert (struct tgl_state *TLS, struct tgl_webpage *P) {
  TLS->webpage_tree = tree_insert_webpage (TLS->webpage_tree, P, lrand48 ());
}

void tglp_peer_insert_name (struct tgl_state *TLS, tgl_peer_t *P) {
  TLS->peer_by_name_tree = tree_insert_peer_by_name (TLS->peer_by_name_tree, P, lrand48 ());
}

void tglp_peer_delete_name (struct tgl_state *TLS, tgl_peer_t *P) {
  TLS->peer_by_name_tree = tree_delete_peer_by_name (TLS->peer_by_name_tree, P);
}

tgl_peer_t *tgl_peer_get (struct tgl_state *TLS, tgl_peer_id_t id) {
  static tgl_peer_t U;
  U.id = id;
  return tree_lookup_peer (TLS->peer_tree, &U);
}

struct tgl_message *tgl_message_get (struct tgl_state *TLS, long long id) {
  struct tgl_message M;
  M.id = id;
  return tree_lookup_message (TLS->message_tree, &M);
}

tgl_peer_t *tgl_peer_get_by_name (struct tgl_state *TLS, const char *s) {
  static tgl_peer_t P;
  P.print_name = (void *)s;
  tgl_peer_t *R = tree_lookup_peer_by_name (TLS->peer_by_name_tree, &P);
  return R;
}

void tgl_peer_iterator_ex (struct tgl_state *TLS, void (*it)(tgl_peer_t *P, void *extra), void *extra) {
  tree_act_ex_peer (TLS->peer_tree, it, extra);
}

int tgl_complete_user_list (struct tgl_state *TLS, int index, const char *text, int len, char **R) {
  index ++;
  while (index < TLS->peer_num && (!TLS->Peers[index]->print_name || strncmp (TLS->Peers[index]->print_name, text, len) || tgl_get_peer_type (TLS->Peers[index]->id) != TGL_PEER_USER)) {
    index ++;
  }
  if (index < TLS->peer_num) {
    *R = strdup (TLS->Peers[index]->print_name);
    assert (*R);
    return index;
  } else {
    return -1;
  }
}

int tgl_complete_chat_list (struct tgl_state *TLS, int index, const char *text, int len, char **R) {
  index ++;
  while (index < TLS->peer_num && (!TLS->Peers[index]->print_name || strncmp (TLS->Peers[index]->print_name, text, len) || tgl_get_peer_type (TLS->Peers[index]->id) != TGL_PEER_CHAT)) {
    index ++;
  }
  if (index < TLS->peer_num) {
    *R = strdup (TLS->Peers[index]->print_name);
    assert (*R);
    return index;
  } else {
    return -1;
  }
}

int tgl_complete_encr_chat_list (struct tgl_state *TLS, int index, const char *text, int len, char **R) {
  index ++;
  while (index < TLS->peer_num && (!TLS->Peers[index]->print_name || strncmp (TLS->Peers[index]->print_name, text, len) || tgl_get_peer_type (TLS->Peers[index]->id) != TGL_PEER_ENCR_CHAT)) {
    index ++;
  }
  if (index < TLS->peer_num) {
    *R = strdup (TLS->Peers[index]->print_name);
    assert (*R);
    return index;
  } else {
    return -1;
  }
}

int tgl_complete_peer_list (struct tgl_state *TLS, int index, const char *text, int len, char **R) {
  index ++;
  while (index < TLS->peer_num && (!TLS->Peers[index]->print_name || strncmp (TLS->Peers[index]->print_name, text, len))) {
    index ++;
  }
  if (index < TLS->peer_num) {
    *R = strdup (TLS->Peers[index]->print_name);
    assert (*R);
    return index;
  } else {
    return -1;
  }
}

int tgl_secret_chat_for_user (struct tgl_state *TLS, tgl_peer_id_t user_id) {
    int index = 0;
    while (index < TLS->peer_num && (tgl_get_peer_type (TLS->Peers[index]->id) != TGL_PEER_ENCR_CHAT || TLS->Peers[index]->encr_chat.user_id != tgl_get_peer_id (user_id) || TLS->Peers[index]->encr_chat.state != sc_ok)) {
        index ++;
    }
    if (index < TLS->peer_num) {
        return tgl_get_peer_id (TLS->Peers[index]->encr_chat.id);
    } else {
        return -1;
    }
}

void tgls_free_peer_gw (tgl_peer_t *P, void *TLS) {
  tgls_free_peer (TLS, P);
}

void tgls_free_message_gw (struct tgl_message *M, void *TLS) {
  tgls_free_message (TLS, M);
}

void tgl_free_all (struct tgl_state *TLS) {
  tree_act_ex_peer (TLS->peer_tree, tgls_free_peer_gw, TLS);
  TLS->peer_tree = tree_clear_peer (TLS->peer_tree);
  TLS->peer_by_name_tree = tree_clear_peer_by_name (TLS->peer_by_name_tree);
  tree_act_ex_message (TLS->message_tree, tgls_free_message_gw, TLS);
  TLS->message_tree = tree_clear_message (TLS->message_tree);
  tree_act_ex_message (TLS->message_unsent_tree, tgls_free_message_gw, TLS);
  TLS->message_unsent_tree = tree_clear_message (TLS->message_unsent_tree);
  tglq_query_free_all (TLS);

  if (TLS->encr_prime) { tfree (TLS->encr_prime, 256); }


  if (TLS->binlog_name) { tfree_str (TLS->binlog_name); }
  if (TLS->auth_file) { tfree_str (TLS->auth_file); }
  if (TLS->downloads_directory) { tfree_str (TLS->downloads_directory); }

  int i;
  for (i = 0; i < TLS->rsa_key_num; i++) {
    tfree_str (TLS->rsa_key_list[i]);
  }

  for (i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i]) {
    tgls_free_dc (TLS, TLS->DC_list[i]);
  }
  BN_CTX_free (TLS->BN_ctx);
  tgls_free_pubkey (TLS);

  if (TLS->ev_login) { TLS->timer_methods->free (TLS->ev_login); }
  if (TLS->online_updates_timer) { TLS->timer_methods->free (TLS->online_updates_timer); }
}

int tgl_print_stat (struct tgl_state *TLS, char *s, int len) {
  return tsnprintf (s, len, 
    "users_allocated\t%d\n"
    "chats_allocated\t%d\n"
    "encr_chats_allocated\t%d\n"
    "peer_num\t%d\n"
    "messages_allocated\t%d\n",
    TLS->users_allocated,
    TLS->chats_allocated,
    TLS->encr_chats_allocated,
    TLS->peer_num,
    TLS->messages_allocated
    );
}

void tglf_fetch_int_array (int *dst, struct tl_ds_vector *src, int len) {
  int i;
  assert (len <= *src->f1);
  for (i = 0; i < len; i++) {
    dst[i] = *(int *)src->f2[i];
  }
}

void tglf_fetch_int_tuple (int *dst, int **src, int len) {
  int i;
  for (i = 0; i < len; i++) {
    dst[i] = *src[i];
  }
}


void tgls_messages_mark_read (struct tgl_state *TLS, struct tgl_message *M, int out, int seq) {
  while (M && M->id > seq) { 
    if ((M->flags & TGLMF_OUT) == out) {
      if (!(M->flags & TGLMF_UNREAD)) {
        return;
      }
    }
    M = M->next; 
  }
  while (M) {
    if ((M->flags & TGLMF_OUT) == out) {
      if (M->flags & TGLMF_UNREAD) {
        M->flags &= ~TGLMF_UNREAD;
        TLS->callback.marked_read (TLS, 1, &M);
      } else {
        return;
      }
    }
    M = M->next; 
  }
}
  
void tgls_insert_random2local (struct tgl_state *TLS, long long random_id, int local_id) {
  struct random2local *X = talloc (sizeof (*X));
  X->random_id = random_id;
  X->local_id = local_id;

  struct random2local *R = tree_lookup_random_id (TLS->random_id_tree, X);
  assert (!R);
  
  TLS->random_id_tree = tree_insert_random_id (TLS->random_id_tree, X, lrand48 ());
}

int tgls_get_local_by_random (struct tgl_state *TLS, long long random_id) {
  struct random2local X;
  X.random_id = random_id;
  struct random2local *Y = tree_lookup_random_id (TLS->random_id_tree, &X);
  if (Y) { 
    TLS->random_id_tree = tree_delete_random_id (TLS->random_id_tree, Y);
    int y = Y->local_id;
    tfree (Y, sizeof (*Y));
    return y;
  } else {
    return 0;
  }
}
