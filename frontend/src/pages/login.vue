<script setup>
import {ref} from 'vue';
import router from "@/router";
import {useAuthStore} from "@/stores/auth";
import BackButton from "@/components/BackButton.vue";

const visible = ref(false);
const isFocused = ref(false);
const alertMessage = ref('');
const alertVisible = ref(false);
const isAuthenticated = ref(false);

const authStore = useAuthStore();

const form = ref({
  email: '',
  password: '',
});

const handleFocus = () => {
  isFocused.value = true;
};

const handleBlur = () => {
  isFocused.value = false;
};

const submit = async () => {
  try {
    console.log(form.value);
    await authStore.login(form.value);
    await router.push('/');
    window.location.reload();
  } catch (error) {
    console.log(error);
    if (error.response.status >= 400) {
      alertMessage.value = error.response.data.error;
      alertVisible.value = true;
    }
  }
}

onMounted(async () => {
  isAuthenticated.value = authStore.auth.isAuthenticated;
  if (isAuthenticated.value) await router.push('/');
})
</script>

<template>
  <v-container fluid class="fill-height bg-primary">
    <v-row>
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" class="pt-8">
        <BackButton color="white"/>
      </v-col>
      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <div class="d-flex flex-column justify-center align-center">
          <v-img src="/logo.png" width="200" height="200"/>
          <span class="text-h4 font-weight-medium pt-2 pb-4 pb-sm-16">GASTROZOOM</span>
        </div>

        <v-form @submit.prevent="submit">
          <v-text-field density="compact" placeholder="Email" prepend-inner-icon="mdi-email-outline" rounded
                        variant="outlined" v-model="form.email" class="mb-1" append-inner-icon="."/>

          <v-text-field placeholder="Unesite lozinku" v-model="form.password" :type="visible ? 'text' : 'password'"
                        prepend-inner-icon="mdi-lock-outline" variant="outlined" rounded density="compact"
                        @focus="handleFocus" @blur="handleBlur" class="mb-4"
          >
            <template v-slot:append-inner>
              <v-icon @click="visible = !visible">
                {{ isFocused ? (visible ? 'mdi-eye-off' : 'mdi-eye') : undefined }}
              </v-icon>
            </template>
          </v-text-field>

          <v-alert v-model="alertVisible" density="compact" variant="tonal" type="error" color="white" class="mb-4"
                   rounded="xl">
            {{ alertMessage }}
          </v-alert>

          <v-btn type="submit" block variant="flat" color="white" size="large" class="mb-8 text-primary mt-2" rounded>
            Prijavi se
          </v-btn>
        </v-form>

        <div class="text-center">
          <span>Nemate račun?</span>
          <RouterLink class="text-white font-weight-medium text-decoration-none pl-1" to="/register">
            Kreirajte novi!
          </RouterLink>
        </div>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
</style>
