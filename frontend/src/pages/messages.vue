<script setup>

import BackButton from "@/components/BackButton.vue";
import {useMessageStore} from "@/stores/message";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";

const messageStore = useMessageStore();
const authStore = useAuthStore();

const messages = ref([]);

onMounted(async () => {
  await messageStore.fetchMessages();
  messages.value = messageStore.messages;
  if (!authStore.auth.isAuthenticated) await router.push('/login');
});

const formatDate = (date) => {
  const newDate = new Date(date);
  if (isNaN(newDate.getDate())) {
    return 'Invalid date';
  }

  return new Intl.DateTimeFormat('hr-HR').format(newDate);
};

const deleteMessage = async (id) => {
  await messageStore.deleteMessage(id);
  await messageStore.fetchMessages();
  messages.value = messageStore.messages;
};

const deleteAllMessages = async () => {
  for (const message of messages.value) {
    await messageStore.deleteMessage(message.id);
  }
  await messageStore.fetchMessages();
  messages.value = messageStore.messages;
};
</script>

<template>

  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Obavjesti</h1>
        </div>
      </v-col>
    </v-row>
    <v-row class="pb-16">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3"
             class="d-flex justify-end mb-2"
      >
        <v-btn v-if="messages.length > 0" icon="mdi-notification-clear-all" color="primary" variant="tonal"
               class="custom-radius mx-2 mx-sm-4" @click="deleteAllMessages"
        />
      </v-col>
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3"
             class="d-flex justify-center mb-2" v-if="messages.length === 0"
      >
        <h1 class="text-h4 text-sm-h3 text-primary text-center">Nema obavjesti</h1>
      </v-col>
      <v-col v-for="message in messages" cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3">
          <v-card :key="message.id" class="d-flex mb-8 align-center custom-shadow" rounded="xl" variant="text">
            <template v-slot:prepend>
              <v-icon class="text-primary">mdi-bell-outline</v-icon>
            </template>
            <v-card-text class="d-flex flex-column align-center mt-4 w-50 w-sm-66 w-md-75">
              <v-card-title class="mr-auto text-h6 text-sm-h5 font-weight-medium">{{ message.title }}</v-card-title>
              <v-card-subtitle class="mr-auto text-subtitle-2 text-sm-subtitle-2">{{ formatDate(message.createdAt) }}</v-card-subtitle>
              <v-card-text class="mr-auto text-subtitle-1 text-sm-h6 font-weight-regular">{{ message.text }}</v-card-text>
            </v-card-text>
            <v-card-actions>
              <v-btn color="primary" variant="plain"
                     icon="mdi-close" @click="deleteMessage(message.id)"
              />
            </v-card-actions>
          </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
