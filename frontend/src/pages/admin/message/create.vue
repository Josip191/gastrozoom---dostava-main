<script setup>
import BackButton from "@/components/BackButton.vue";
import {useMessageStore} from "@/stores/message";
import {ref} from "vue";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";

const form = ref({
  title: "",
  text: "",
  type: "SYSTEM_NOTIFICATION",
});

const alertMessage = ref('');
const alertVisible = ref(false);

const messageStore = useMessageStore();
const authStore = useAuthStore();

const submit = async () => {
  try {
    await messageStore.createMessage(form.value);
    await router.push('/messages');
    window.location.reload();
  } catch (error) {
    if (error.response.status >= 400) {
      alertMessage.value = error.response.data.error;
      alertVisible.value = true;
    }
  }
};

onMounted(async () => {
  if (authStore.auth.role !== 'ADMIN') await router.push('/');
})

</script>

<template>
  <v-container fluid class="fill-height">
    <v-row class="pb-8">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" class="d-flex">
        <BackButton />
      </v-col>
      <v-col cols="10" sm="8" md="6" lg="4"  offset="1" offset-sm="2" offset-md="3" offset-lg="4">
        <v-icon size="8rem" class="text-center text-primary w-100 mb-4">mdi-message-plus</v-icon>
        <h4 class="text-h4 text-center font-weight-medium pb-12">Kreiraj obavjest</h4>
        <v-form @submit.prevent="submit">
          <v-text-field density="compact" placeholder="Unesi naslov obavjesti" rounded
                        variant="outlined" v-model="form.title" class="mb-1" append-inner-icon="."/>
          <v-textarea maxlenght="250" counter density="compact" placeholder="Unesi tekst obavjesti" rounded
                      variant="outlined" v-model="form.text" class="mb-4" append-inner-icon="."/>

          <v-alert v-model="alertVisible" density="compact" variant="tonal" type="error" class="mb-4"
                   rounded="xl">
            {{ alertMessage }}
          </v-alert>

          <v-btn type="submit" prepend-icon="mdi-plus" block variant="flat" color="primary" size="large" class="mb-8" rounded>
            Objavi obavjest
          </v-btn>
        </v-form>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
